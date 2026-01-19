use anyhow::Result;
use rig::completion::Prompt;

use crate::models::{Extension, Finding, Endpoint, Severity, Category};
use super::LlmClient;

/// Different types of analysis tasks that can be performed by the LLM
#[derive(Debug, Clone)]
pub enum AnalysisTask {
    /// Review the manifest.json for security issues
    ManifestReview,
    /// Analyze JavaScript code for suspicious patterns
    ScriptAnalysis,
    /// Analyze discovered endpoints for security concerns
    EndpointAnalysis,
    /// Generate a final summary of all findings
    FinalSummary,
    /// Deobfuscate a JavaScript snippet using sandbox execution
    Deobfuscate(String),
}

/// Results from LLM analysis
#[derive(Debug)]
pub struct LlmAnalysisResult {
    pub findings: Vec<Finding>,
    pub summary: Option<String>,
}

/// Run multiple analysis tasks in parallel using the LLM
pub async fn analyze_with_llm(
    client: &LlmClient,
    extension: &Extension,
    static_findings: &[Finding],
    endpoints: &[Endpoint],
    tasks: Vec<AnalysisTask>,
    model: Option<&str>,
) -> Result<LlmAnalysisResult> {
    let mut all_findings = Vec::new();
    let mut summary = None;

    // Build prompts for each task
    let task_prompts: Vec<(AnalysisTask, String)> = tasks
        .into_iter()
        .map(|task| {
            let prompt = build_prompt(&task, extension, static_findings, endpoints);
            (task, prompt)
        })
        .collect();

    // Run tasks in parallel
    let futures: Vec<_> = task_prompts
        .iter()
        .map(|(task, prompt)| run_task(client, task, prompt, model))
        .collect();

    let results = futures::future::join_all(futures).await;

    // Process results
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(response) => {
                let task = &task_prompts[i].0;
                match task {
                    AnalysisTask::FinalSummary => {
                        summary = Some(response);
                    }
                    _ => {
                        let parsed_findings = parse_findings(&response, task);
                        all_findings.extend(parsed_findings);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("LLM task failed: {}", e);
            }
        }
    }

    Ok(LlmAnalysisResult {
        findings: all_findings,
        summary,
    })
}

/// Default models for each provider
const DEFAULT_OPENAI_MODEL: &str = "gpt-4o-mini";
const DEFAULT_ANTHROPIC_MODEL: &str = "claude-3-haiku-20240307";
const DEFAULT_GEMINI_MODEL: &str = "gemini-3-flash-preview";

/// Run a single analysis task
async fn run_task(
    client: &LlmClient,
    _task: &AnalysisTask,
    prompt: &str,
    model: Option<&str>,
) -> Result<String> {
    match client {
        LlmClient::OpenAi(c) => {
            let model_name = model.unwrap_or(DEFAULT_OPENAI_MODEL);
            let agent = c.agent(model_name).build();
            let response = agent.prompt(prompt).await?;
            Ok(response)
        }
        LlmClient::Anthropic(c) => {
            let model_name = model.unwrap_or(DEFAULT_ANTHROPIC_MODEL);
            let agent = c.agent(model_name).build();
            let response = agent.prompt(prompt).await?;
            Ok(response)
        }
        LlmClient::Gemini(c) => {
            let model_name = model.unwrap_or(DEFAULT_GEMINI_MODEL);
            let agent = c.agent(model_name).build();
            let response = agent.prompt(prompt).await?;
            Ok(response)
        }
    }
}

/// Build a focused prompt for each task type
fn build_prompt(
    task: &AnalysisTask,
    extension: &Extension,
    static_findings: &[Finding],
    endpoints: &[Endpoint],
) -> String {
    match task {
        AnalysisTask::ManifestReview => build_manifest_prompt(extension),
        AnalysisTask::ScriptAnalysis => build_script_prompt(extension),
        AnalysisTask::EndpointAnalysis => build_endpoint_prompt(endpoints),
        AnalysisTask::FinalSummary => build_summary_prompt(extension, static_findings, endpoints),
        AnalysisTask::Deobfuscate(snippet) => build_deobfuscate_prompt(snippet),
    }
}

/// Build prompt for manifest review
fn build_manifest_prompt(extension: &Extension) -> String {
    let manifest_json = extension
        .manifest
        .as_ref()
        .map(|m| serde_json::to_string_pretty(m).unwrap_or_default())
        .unwrap_or_else(|| "No manifest available".to_string());

    format!(
        r#"You are a browser extension security analyst. Analyze this manifest.json for security concerns.

Extension: {} (version: {})

Manifest:
{}

Look for:
1. Overly broad permissions (e.g., <all_urls>, tabs, webRequest)
2. Suspicious host permissions
3. Content scripts injecting into sensitive sites
4. Missing or concerning CSP
5. Unusual background script configurations

For each finding, respond in this format:
FINDING: [SEVERITY] - [TITLE]
DESCRIPTION: [Brief description of the security concern]

Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

If no security concerns are found, respond with "NO_FINDINGS"."#,
        extension.name.as_deref().unwrap_or(&extension.id),
        extension.version.as_deref().unwrap_or("unknown"),
        manifest_json
    )
}

/// Build prompt for script analysis
fn build_script_prompt(extension: &Extension) -> String {
    let scripts: Vec<String> = extension
        .files
        .iter()
        .filter(|f| f.file_type == crate::models::FileType::JavaScript)
        .filter_map(|f| {
            f.content.as_ref().map(|c| {
                let preview = if c.len() > 2000 {
                    format!("{}... [truncated]", &c[..2000])
                } else {
                    c.clone()
                };
                format!("// File: {}\n{}", f.path.display(), preview)
            })
        })
        .take(5) // Limit to 5 files to avoid token limits
        .collect();

    let scripts_text = if scripts.is_empty() {
        "No JavaScript files available".to_string()
    } else {
        scripts.join("\n\n---\n\n")
    };

    format!(
        r#"You are a browser extension security analyst. Analyze these JavaScript files for suspicious patterns.

{}

Look for:
1. Dynamic code execution (eval, Function constructor, setTimeout with strings)
2. Obfuscation techniques (base64 encoded strings, character code manipulation)
3. Data exfiltration (sending browsing data, credentials, or personal info)
4. Credential theft attempts
5. DOM manipulation for phishing
6. Cryptocurrency mining code
7. Remote code loading

For each finding, respond in this format:
FINDING: [SEVERITY] - [TITLE]
DESCRIPTION: [Brief description of what the code is doing and why it's concerning]

Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

If no security concerns are found, respond with "NO_FINDINGS"."#,
        scripts_text
    )
}

/// Build prompt for endpoint analysis
fn build_endpoint_prompt(endpoints: &[Endpoint]) -> String {
    let endpoints_text: String = endpoints
        .iter()
        .take(20) // Limit to avoid token issues
        .map(|e| {
            format!(
                "- {} {} (found at {})",
                e.method.as_ref().map(|m| m.as_str()).unwrap_or("?"),
                e.url,
                e.location
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let endpoints_text = if endpoints_text.is_empty() {
        "No endpoints discovered".to_string()
    } else {
        endpoints_text
    };

    format!(
        r#"You are a browser extension security analyst. Analyze these network endpoints discovered in a browser extension.

Endpoints:
{}

Look for:
1. Known malicious domains or IPs
2. Suspicious data collection endpoints (analytics, telemetry that's excessive)
3. Non-HTTPS endpoints that might leak sensitive data
4. Command and control (C2) patterns
5. Unusual API endpoints that don't match the extension's stated purpose
6. Data exfiltration endpoints

For each finding, respond in this format:
FINDING: [SEVERITY] - [TITLE]
DESCRIPTION: [Brief description of the security concern with this endpoint]

Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

If no security concerns are found, respond with "NO_FINDINGS"."#,
        endpoints_text
    )
}

/// Build prompt for final summary
fn build_summary_prompt(
    extension: &Extension,
    findings: &[Finding],
    endpoints: &[Endpoint],
) -> String {
    let findings_text: String = findings
        .iter()
        .map(|f| format!("- [{}] {}: {}", f.severity.as_str(), f.title, f.description))
        .collect::<Vec<_>>()
        .join("\n");

    let findings_text = if findings_text.is_empty() {
        "No findings from static analysis".to_string()
    } else {
        findings_text
    };

    format!(
        r#"You are a browser extension security analyst. Generate a concise executive summary of the security analysis.

Extension: {} (version: {})
Source: {:?}

Static Analysis Findings:
{}

Network Endpoints Found: {}

Provide:
1. Overall risk assessment (CRITICAL, HIGH, MEDIUM, LOW, SAFE)
2. Key concerns (2-3 bullet points)
3. Recommendations (2-3 bullet points)

Keep the summary concise (under 200 words)."#,
        extension.name.as_deref().unwrap_or(&extension.id),
        extension.version.as_deref().unwrap_or("unknown"),
        extension.source,
        findings_text,
        endpoints.len()
    )
}

/// Build prompt for deobfuscation analysis
fn build_deobfuscate_prompt(snippet: &str) -> String {
    use crate::sandbox::execute_snippet;

    let result = execute_snippet(snippet, 2000);

    let decoded_text = if result.decoded_strings.is_empty() {
        "No strings were decoded.".to_string()
    } else {
        result
            .decoded_strings
            .iter()
            .map(|d| format!("- {}('{}') → '{}'", d.function, d.input, d.output))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let calls_text = if result.api_calls.is_empty() {
        "No API calls were made.".to_string()
    } else {
        result
            .api_calls
            .iter()
            .map(|c| format!("- {}({})", c.function,
                c.arguments.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let error_text = result
        .error
        .map(|e| format!("\n\nExecution error: {}", e))
        .unwrap_or_default();

    format!(
        r#"I executed this JavaScript snippet in a sandbox:

```javascript
{}
```

Results:

**Decoded strings:**
{}

**API calls traced:**
{}

**Final value:** {}{}

Based on these results, explain what this code is trying to do. Is it malicious? What data does it access or exfiltrate?"#,
        snippet,
        decoded_text,
        calls_text,
        result.final_value.as_deref().unwrap_or("(none)"),
        error_text
    )
}

/// Parse LLM response to extract findings
fn parse_findings(response: &str, task: &AnalysisTask) -> Vec<Finding> {
    let mut findings = Vec::new();

    if response.contains("NO_FINDINGS") {
        return findings;
    }

    // Parse FINDING: [SEVERITY] - [TITLE] format
    let lines: Vec<&str> = response.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        if line.starts_with("FINDING:") {
            // Parse severity and title
            let content = line.strip_prefix("FINDING:").unwrap_or("").trim();

            if let Some((severity_str, title)) = parse_finding_line(content) {
                let severity = parse_severity(&severity_str);
                let category = task_to_category(task);

                // Look for description on next line
                let description = if i + 1 < lines.len() {
                    let next_line = lines[i + 1].trim();
                    if next_line.starts_with("DESCRIPTION:") {
                        i += 1;
                        next_line
                            .strip_prefix("DESCRIPTION:")
                            .unwrap_or("")
                            .trim()
                            .to_string()
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };

                let finding = Finding::new(severity, category, title).with_description(description);
                findings.push(finding);
            }
        }

        i += 1;
    }

    findings
}

/// Parse a finding line to extract severity and title
fn parse_finding_line(content: &str) -> Option<(String, String)> {
    // Expected format: [SEVERITY] - Title
    // or: SEVERITY - Title
    let content = content.trim();

    // Try [SEVERITY] format first
    if content.starts_with('[') {
        if let Some(end_bracket) = content.find(']') {
            let severity = content[1..end_bracket].to_string();
            let rest = content[end_bracket + 1..].trim();
            let title = rest.strip_prefix('-').unwrap_or(rest).trim().to_string();
            return Some((severity, title));
        }
    }

    // Try SEVERITY - Title format
    if let Some(dash_pos) = content.find(" - ") {
        let severity = content[..dash_pos].trim().to_string();
        let title = content[dash_pos + 3..].trim().to_string();
        return Some((severity, title));
    }

    None
}

/// Parse severity string to Severity enum
fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Map analysis task to finding category
fn task_to_category(task: &AnalysisTask) -> Category {
    match task {
        AnalysisTask::ManifestReview => Category::Permission,
        AnalysisTask::ScriptAnalysis => Category::ApiUsage,
        AnalysisTask::EndpointAnalysis => Category::Network,
        AnalysisTask::FinalSummary => Category::ApiUsage,
        AnalysisTask::Deobfuscate(_) => Category::Obfuscation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert!(matches!(parse_severity("CRITICAL"), Severity::Critical));
        assert!(matches!(parse_severity("high"), Severity::High));
        assert!(matches!(parse_severity("Medium"), Severity::Medium));
        assert!(matches!(parse_severity("low"), Severity::Low));
        assert!(matches!(parse_severity("unknown"), Severity::Info));
    }

    #[test]
    fn test_parse_finding_line() {
        let (sev, title) = parse_finding_line("[HIGH] - Suspicious eval usage").unwrap();
        assert_eq!(sev, "HIGH");
        assert_eq!(title, "Suspicious eval usage");

        let (sev, title) = parse_finding_line("MEDIUM - Data exfiltration risk").unwrap();
        assert_eq!(sev, "MEDIUM");
        assert_eq!(title, "Data exfiltration risk");
    }

    #[test]
    fn test_parse_findings_no_findings() {
        let response = "NO_FINDINGS";
        let findings = parse_findings(response, &AnalysisTask::ManifestReview);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_findings() {
        let response = r#"FINDING: [HIGH] - Overly broad permissions
DESCRIPTION: The extension requests <all_urls> which grants access to all websites.

FINDING: [MEDIUM] - Suspicious host permission
DESCRIPTION: Access to banking sites is unusual for this type of extension."#;

        let findings = parse_findings(response, &AnalysisTask::ManifestReview);
        assert_eq!(findings.len(), 2);
        assert!(matches!(findings[0].severity, Severity::High));
        assert_eq!(findings[0].title, "Overly broad permissions");
        assert!(matches!(findings[1].severity, Severity::Medium));
    }
}
