use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use rig::client::CompletionClient;
use rig::completion::Prompt;

use super::provider::LlmClient;
use super::tools::{
    ExtensionContext, ReadFileTool, RunSandboxTool, SearchCodeTool, SubmitVerdictTool,
};
use crate::models::{Extension, Finding, Severity};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_TOOL_CALLS: usize = 50;
const DEFAULT_OPENAI_MODEL: &str = "gpt-4o-mini";
const DEFAULT_ANTHROPIC_MODEL: &str = "claude-3-haiku-20240307";
const DEFAULT_GEMINI_MODEL: &str = "gemini-3-flash-preview";

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// The outcome of an agentic review of a single finding.
#[derive(Debug)]
pub enum Verdict {
    /// Finding confirmed as valid at its current severity.
    Confirm { reasoning: String },
    /// Finding is valid but severity should be adjusted.
    Downgrade {
        new_severity: Severity,
        reasoning: String,
    },
    /// Finding is a false positive and should be removed.
    Dismiss { reasoning: String },
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Extract the first JSON object from `text` (which may contain surrounding prose).
fn extract_json(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end >= start {
        Some(&text[start..=end])
    } else {
        None
    }
}

/// Parse a severity string (case-insensitive) into a `Severity` enum variant.
fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

/// Parse a verdict from LLM text output that contains a JSON object with
/// `action`, optional `new_severity`, and `reasoning` fields.
pub fn parse_verdict(text: &str) -> Option<Verdict> {
    let json_str = extract_json(text)?;
    let value: serde_json::Value = serde_json::from_str(json_str).ok()?;

    let action = value.get("action")?.as_str()?;
    let reasoning = value.get("reasoning")?.as_str()?.to_string();

    match action {
        "confirm" => Some(Verdict::Confirm { reasoning }),
        "adjust_severity" => {
            let sev_str = value.get("new_severity")?.as_str()?;
            let new_severity = parse_severity(sev_str)?;
            Some(Verdict::Downgrade {
                new_severity,
                reasoning,
            })
        }
        "dismiss" => Some(Verdict::Dismiss { reasoning }),
        _ => None,
    }
}

/// Apply a verdict to a finding.
///
/// - `Confirm`: attaches reasoning, keeps severity, returns the finding.
/// - `Downgrade`: changes severity, attaches reasoning with "Downgraded from ..." prefix.
/// - `Dismiss`: logs at debug level and returns `None`.
pub fn apply_verdict(finding: Finding, verdict: Verdict) -> Option<Finding> {
    match verdict {
        Verdict::Confirm { reasoning } => Some(finding.with_review_reasoning(reasoning)),
        Verdict::Downgrade {
            new_severity,
            reasoning,
        } => {
            let old_severity = finding.severity.as_str();
            let full_reasoning = format!("Downgraded from {old_severity}. {reasoning}");
            let mut updated = finding.with_review_reasoning(full_reasoning);
            updated.severity = new_severity;
            Some(updated)
        }
        Verdict::Dismiss { reasoning } => {
            tracing::debug!("Dismissed finding '{}': {}", finding.title, reasoning);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Prompt builders
// ---------------------------------------------------------------------------

/// Build the system prompt that describes the review agent's role and lists
/// available extension files.
fn build_system_prompt(extension: &Extension) -> String {
    let file_list: String = extension
        .files
        .iter()
        .map(|f| format!("  - {} ({:?})", f.path.display(), f.file_type))
        .collect::<Vec<_>>()
        .join("\n");

    let name = extension.name.as_deref().unwrap_or(&extension.id);
    let version = extension.version.as_deref().unwrap_or("unknown");

    format!(
        r#"You are a security expert reviewing findings from a static analysis of a browser extension.

Extension: {name} (version: {version})

Available files in this extension:
{file_list}

Your job is to investigate each finding carefully using the tools provided:
- Use `read_file` to examine source code in the extension.
- Use `search_code` to find patterns across all files.
- Use `run_sandbox` to deobfuscate suspicious JavaScript snippets.
- Use `submit_verdict` to deliver your final assessment.

For each finding, you MUST call `submit_verdict` exactly once with:
- action: "confirm" (finding is valid), "adjust_severity" (valid but wrong severity), or "dismiss" (false positive)
- new_severity: only when action is "adjust_severity", one of "critical", "high", "medium", "low", "info"
- reasoning: a brief explanation of your assessment

Investigate thoroughly before submitting your verdict. Read the relevant code, search for related patterns, and use the sandbox to decode obfuscated strings if needed."#
    )
}

/// Build the per-finding user prompt that describes the finding to review.
fn build_finding_prompt(finding: &Finding) -> String {
    let mut parts = vec![
        format!("## Finding to Review"),
        format!("**Title:** {}", finding.title),
        format!("**Severity:** {}", finding.severity.as_str()),
        format!("**Category:** {}", finding.category.as_str()),
    ];

    if !finding.description.is_empty() {
        parts.push(format!("**Description:** {}", finding.description));
    }

    if let Some(ref location) = finding.location {
        parts.push(format!("**Location:** {}", location));
    }

    if let Some(ref snippet) = finding.code_snippet {
        parts.push(format!("**Code snippet:**\n```\n{}\n```", snippet));
    }

    parts.push(String::new());
    parts.push(
        "Investigate this finding using the available tools, then call `submit_verdict` with your assessment."
            .to_string(),
    );

    parts.join("\n")
}

// ---------------------------------------------------------------------------
// Review loop
// ---------------------------------------------------------------------------

/// Review a single finding by building a rig agent with all 4 tools and
/// running a multi-turn conversation.
async fn review_single_finding(
    client: &LlmClient,
    context: &ExtensionContext,
    system_prompt: &str,
    finding_prompt: &str,
    model: Option<&str>,
) -> Result<String> {
    let read_file = ReadFileTool::new(context.clone());
    let search_code = SearchCodeTool::new(context.clone());
    let run_sandbox = RunSandboxTool;
    let submit_verdict = SubmitVerdictTool;

    match client {
        LlmClient::OpenAi(c) => {
            let model_name = model.unwrap_or(DEFAULT_OPENAI_MODEL);
            let agent = c
                .agent(model_name)
                .preamble(system_prompt)
                .tool(read_file)
                .tool(search_code)
                .tool(run_sandbox)
                .tool(submit_verdict)
                .build();
            let response = agent
                .prompt(finding_prompt)
                .multi_turn(MAX_TOOL_CALLS)
                .await?;
            Ok(response)
        }
        LlmClient::Anthropic(c) => {
            let model_name = model.unwrap_or(DEFAULT_ANTHROPIC_MODEL);
            let agent = c
                .agent(model_name)
                .preamble(system_prompt)
                .tool(read_file)
                .tool(search_code)
                .tool(run_sandbox)
                .tool(submit_verdict)
                .build();
            let response = agent
                .prompt(finding_prompt)
                .multi_turn(MAX_TOOL_CALLS)
                .await?;
            Ok(response)
        }
        LlmClient::Gemini(c) => {
            let model_name = model.unwrap_or(DEFAULT_GEMINI_MODEL);
            let agent = c
                .agent(model_name)
                .preamble(system_prompt)
                .tool(read_file)
                .tool(search_code)
                .tool(run_sandbox)
                .tool(submit_verdict)
                .build();
            let response = agent
                .prompt(finding_prompt)
                .multi_turn(MAX_TOOL_CALLS)
                .await?;
            Ok(response)
        }
    }
}

/// Review all findings using an agentic LLM loop. Each finding is reviewed
/// sequentially. On error, the original finding is kept (fail-safe).
pub async fn review_findings(
    client: &LlmClient,
    extension: &Extension,
    findings: Vec<Finding>,
    model: Option<&str>,
) -> Result<Vec<Finding>> {
    let context = ExtensionContext {
        files: Arc::new(extension.files.clone()),
        extract_path: Arc::new(
            extension
                .extract_path
                .clone()
                .unwrap_or_else(|| PathBuf::from(".")),
        ),
    };

    let system_prompt = build_system_prompt(extension);
    let mut reviewed: Vec<Finding> = Vec::new();

    for (i, finding) in findings.into_iter().enumerate() {
        let finding_prompt = build_finding_prompt(&finding);

        tracing::info!(
            "Reviewing finding {}: {} [{}]",
            i + 1,
            finding.title,
            finding.severity.as_str()
        );

        match review_single_finding(client, &context, &system_prompt, &finding_prompt, model).await
        {
            Ok(response) => {
                if let Some(verdict) = parse_verdict(&response) {
                    tracing::info!("Verdict for '{}': {:?}", finding.title, verdict);
                    if let Some(updated_finding) = apply_verdict(finding, verdict) {
                        reviewed.push(updated_finding);
                    }
                    // Dismiss => apply_verdict returns None, finding is dropped
                } else {
                    tracing::warn!(
                        "Could not parse verdict for '{}', keeping original finding",
                        finding.title
                    );
                    reviewed.push(finding);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Review failed for '{}': {}, keeping original finding",
                    finding.title,
                    e
                );
                reviewed.push(finding);
            }
        }
    }

    Ok(reviewed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Severity};

    // -- extract_json tests --

    #[test]
    fn test_extract_json_with_surrounding_text() {
        let text =
            r#"Here is my verdict: {"action": "confirm", "reasoning": "looks legit"} that's it"#;
        let json = extract_json(text).unwrap();
        assert_eq!(json, r#"{"action": "confirm", "reasoning": "looks legit"}"#);
    }

    #[test]
    fn test_extract_json_bare() {
        let text = r#"{"action": "dismiss", "reasoning": "false positive"}"#;
        let json = extract_json(text).unwrap();
        assert_eq!(text, json);
    }

    #[test]
    fn test_extract_json_no_json() {
        assert!(extract_json("no json here").is_none());
    }

    // -- parse_verdict tests --

    #[test]
    fn test_parse_verdict_confirm() {
        let text = r#"{"action": "confirm", "reasoning": "This eval usage is real"}"#;
        let verdict = parse_verdict(text).unwrap();
        match verdict {
            Verdict::Confirm { reasoning } => {
                assert_eq!(reasoning, "This eval usage is real");
            }
            _ => panic!("Expected Confirm verdict"),
        }
    }

    #[test]
    fn test_parse_verdict_downgrade() {
        let text = r#"{"action": "adjust_severity", "new_severity": "low", "reasoning": "Not exploitable"}"#;
        let verdict = parse_verdict(text).unwrap();
        match verdict {
            Verdict::Downgrade {
                new_severity,
                reasoning,
            } => {
                assert!(matches!(new_severity, Severity::Low));
                assert_eq!(reasoning, "Not exploitable");
            }
            _ => panic!("Expected Downgrade verdict"),
        }
    }

    #[test]
    fn test_parse_verdict_dismiss() {
        let text = r#"{"action": "dismiss", "reasoning": "This is a standard library usage"}"#;
        let verdict = parse_verdict(text).unwrap();
        match verdict {
            Verdict::Dismiss { reasoning } => {
                assert_eq!(reasoning, "This is a standard library usage");
            }
            _ => panic!("Expected Dismiss verdict"),
        }
    }

    #[test]
    fn test_parse_verdict_fails_on_garbage() {
        assert!(parse_verdict("not json at all").is_none());
        assert!(parse_verdict("{}").is_none());
        assert!(parse_verdict(r#"{"action": "unknown", "reasoning": "x"}"#).is_none());
        assert!(parse_verdict(r#"{"action": "adjust_severity", "reasoning": "x"}"#).is_none());
    }

    // -- apply_verdict tests --

    fn make_finding() -> Finding {
        Finding::new(Severity::High, Category::ApiUsage, "Eval usage detected")
            .with_description("eval() call found in background.js")
    }

    #[test]
    fn test_apply_verdict_confirm() {
        let finding = make_finding();
        let verdict = Verdict::Confirm {
            reasoning: "Confirmed dangerous".to_string(),
        };
        let result = apply_verdict(finding, verdict).unwrap();
        assert!(matches!(result.severity, Severity::High));
        assert_eq!(
            result.review_reasoning.as_deref(),
            Some("Confirmed dangerous")
        );
    }

    #[test]
    fn test_apply_verdict_downgrade() {
        let finding = make_finding();
        let verdict = Verdict::Downgrade {
            new_severity: Severity::Low,
            reasoning: "Used safely".to_string(),
        };
        let result = apply_verdict(finding, verdict).unwrap();
        assert!(matches!(result.severity, Severity::Low));
        let reasoning = result.review_reasoning.as_deref().unwrap();
        assert!(reasoning.contains("Downgraded from HIGH"));
        assert!(reasoning.contains("Used safely"));
    }

    #[test]
    fn test_apply_verdict_dismiss() {
        let finding = make_finding();
        let verdict = Verdict::Dismiss {
            reasoning: "False positive".to_string(),
        };
        let result = apply_verdict(finding, verdict);
        assert!(result.is_none());
    }
}
