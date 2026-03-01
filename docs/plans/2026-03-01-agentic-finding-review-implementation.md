# Agentic Finding Review Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace rubber-stamp LLM analysis with per-finding agentic review where the LLM investigates code using tools before confirming, downgrading, or dismissing each static finding.

**Architecture:** Each static finding is reviewed individually by a rig-core agent equipped with 4 tools (read_file, search_code, run_sandbox, submit_verdict). The agent uses multi-turn tool calling (max 50 turns) to investigate, then delivers a verdict. Reviewed findings replace originals in the pipeline.

**Tech Stack:** rig-core 0.28 (Tool trait, AgentBuilder, multi_turn), schemars 1.0 (JsonSchema for tool args), existing QuickJS sandbox.

---

### Task 1: Add schemars dependency

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add schemars to dependencies**

In `Cargo.toml`, add under `[dependencies]`:

```toml
schemars = "1.0"
```

**Step 2: Verify it compiles**

Run: `cargo check`
Expected: Compiles with no errors.

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "feat(deps): add schemars for rig tool definitions"
```

---

### Task 2: Add review_reasoning field to Finding

**Files:**
- Modify: `src/models/finding.rs`
- Test: `tests/finding_tests.rs`

**Step 1: Write the failing test**

Create `tests/finding_tests.rs`:

```rust
use extanalyzer::models::{Category, Finding, Severity};

#[test]
fn test_finding_review_reasoning_default_none() {
    let finding = Finding::new(Severity::Medium, Category::Obfuscation, "test");
    assert!(finding.review_reasoning.is_none());
}

#[test]
fn test_finding_with_review_reasoning() {
    let finding = Finding::new(Severity::Medium, Category::Obfuscation, "test")
        .with_review_reasoning("Downgraded: legitimate use of String.fromCharCode for i18n");
    assert_eq!(
        finding.review_reasoning.as_deref(),
        Some("Downgraded: legitimate use of String.fromCharCode for i18n")
    );
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test finding_tests`
Expected: FAIL — `review_reasoning` field and `with_review_reasoning` method don't exist yet.

**Step 3: Add the field and builder method**

In `src/models/finding.rs`, add `review_reasoning: Option<String>` to the `Finding` struct, initialize it to `None` in `Finding::new()`, and add builder method:

```rust
pub review_reasoning: Option<String>,
```

In `Finding::new()`:
```rust
review_reasoning: None,
```

Builder method:
```rust
pub fn with_review_reasoning(mut self, reasoning: impl Into<String>) -> Self {
    self.review_reasoning = Some(reasoning.into());
    self
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --test finding_tests`
Expected: PASS

**Step 5: Commit**

```bash
git add src/models/finding.rs tests/finding_tests.rs
git commit -m "feat(models): add review_reasoning to Finding"
```

---

### Task 3: Implement review tools

**Files:**
- Create: `src/llm/tools.rs`
- Test: inline `#[cfg(test)]` module

**Step 1: Write failing tests for tool args deserialization**

At the bottom of the new `src/llm/tools.rs` file, add tests first (they will fail because the structs don't exist yet):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_file_args_deserialize() {
        let json = r#"{"path": "background.js"}"#;
        let args: ReadFileArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.path, "background.js");
    }

    #[test]
    fn test_search_code_args_deserialize() {
        let json = r#"{"pattern": "fromCharCode"}"#;
        let args: SearchCodeArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.pattern, "fromCharCode");
    }

    #[test]
    fn test_run_sandbox_args_deserialize() {
        let json = r#"{"code": "1+1"}"#;
        let args: RunSandboxArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.code, "1+1");
    }

    #[test]
    fn test_submit_verdict_args_confirm() {
        let json = r#"{"action": "confirm", "reasoning": "legit eval"}"#;
        let args: SubmitVerdictArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.action, "confirm");
        assert!(args.new_severity.is_none());
    }

    #[test]
    fn test_submit_verdict_args_downgrade() {
        let json = r#"{"action": "downgrade", "new_severity": "info", "reasoning": "harmless"}"#;
        let args: SubmitVerdictArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.action, "downgrade");
        assert_eq!(args.new_severity.as_deref(), Some("info"));
    }

    #[test]
    fn test_submit_verdict_args_dismiss() {
        let json = r#"{"action": "dismiss", "reasoning": "false positive"}"#;
        let args: SubmitVerdictArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.action, "dismiss");
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test tools::tests`
Expected: FAIL — module doesn't exist yet.

**Step 3: Implement the tools**

Create `src/llm/tools.rs`:

```rust
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::models::ExtensionFile;
use crate::sandbox::execute_snippet;

/// Shared context for all review tools — the extension's extracted files
#[derive(Clone)]
pub struct ExtensionContext {
    pub files: Arc<Vec<ExtensionFile>>,
    pub extract_path: Arc<PathBuf>,
}

// ── ReadFile tool ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ReadFileArgs {
    pub path: String,
}

#[derive(Debug, thiserror::Error)]
#[error("Tool error: {0}")]
pub struct ReviewToolError(pub String);

#[derive(Clone, Serialize, Deserialize)]
pub struct ReadFileTool {
    #[serde(skip)]
    context: Option<ExtensionContext>,
}

impl ReadFileTool {
    pub fn new(context: ExtensionContext) -> Self {
        Self {
            context: Some(context),
        }
    }
}

const MAX_FILE_SIZE: usize = 50_000;

impl Tool for ReadFileTool {
    const NAME: &'static str = "read_file";
    type Error = ReviewToolError;
    type Args = ReadFileArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "read_file".to_string(),
            description: "Read a file from the extension by its relative path. Returns the file contents.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the file within the extension (e.g. 'background.js', 'src/utils.js')"
                    }
                },
                "required": ["path"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let ctx = self.context.as_ref().ok_or_else(|| ReviewToolError("No context".into()))?;
        let target = Path::new(&args.path);

        // Try to find the file in the extension's file list
        for file in ctx.files.iter() {
            if file.path == target {
                if let Some(ref content) = file.content {
                    if content.len() > MAX_FILE_SIZE {
                        return Ok(format!("{}... [truncated at {} bytes]", &content[..MAX_FILE_SIZE], MAX_FILE_SIZE));
                    }
                    return Ok(content.clone());
                } else {
                    return Ok("[binary file — no text content]".to_string());
                }
            }
        }

        // Fall back to reading from the extract path
        let full_path = ctx.extract_path.join(&args.path);
        match std::fs::read_to_string(&full_path) {
            Ok(content) => {
                if content.len() > MAX_FILE_SIZE {
                    Ok(format!("{}... [truncated at {} bytes]", &content[..MAX_FILE_SIZE], MAX_FILE_SIZE))
                } else {
                    Ok(content)
                }
            }
            Err(_) => Ok(format!("File not found: {}", args.path)),
        }
    }
}

// ── SearchCode tool ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SearchCodeArgs {
    pub pattern: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SearchCodeTool {
    #[serde(skip)]
    context: Option<ExtensionContext>,
}

impl SearchCodeTool {
    pub fn new(context: ExtensionContext) -> Self {
        Self {
            context: Some(context),
        }
    }
}

const MAX_SEARCH_RESULTS: usize = 50;

impl Tool for SearchCodeTool {
    const NAME: &'static str = "search_code";
    type Error = ReviewToolError;
    type Args = SearchCodeArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "search_code".to_string(),
            description: "Search all extension files for a text pattern. Returns matching lines with file paths and line numbers.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Text pattern to search for (substring match, case-sensitive)"
                    }
                },
                "required": ["pattern"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let ctx = self.context.as_ref().ok_or_else(|| ReviewToolError("No context".into()))?;
        let mut results = Vec::new();

        for file in ctx.files.iter() {
            if let Some(ref content) = file.content {
                for (line_num, line) in content.lines().enumerate() {
                    if line.contains(&args.pattern) {
                        results.push(format!("{}:{}: {}", file.path.display(), line_num + 1, line.trim()));
                        if results.len() >= MAX_SEARCH_RESULTS {
                            results.push(format!("... [truncated at {} results]", MAX_SEARCH_RESULTS));
                            return Ok(results.join("\n"));
                        }
                    }
                }
            }
        }

        if results.is_empty() {
            Ok(format!("No matches found for '{}'", args.pattern))
        } else {
            Ok(results.join("\n"))
        }
    }
}

// ── RunSandbox tool ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RunSandboxArgs {
    pub code: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RunSandboxTool;

const SANDBOX_TIMEOUT_MS: u64 = 2000;

impl Tool for RunSandboxTool {
    const NAME: &'static str = "run_sandbox";
    type Error = ReviewToolError;
    type Args = RunSandboxArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "run_sandbox".to_string(),
            description: "Execute a JavaScript snippet in an isolated sandbox. Returns decoded strings, API call traces, and the final expression value. No network or filesystem access. Useful for understanding what obfuscated code actually does.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "JavaScript code to execute in the sandbox"
                    }
                },
                "required": ["code"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let result = execute_snippet(&args.code, SANDBOX_TIMEOUT_MS);

        let mut output = Vec::new();

        if !result.decoded_strings.is_empty() {
            output.push("Decoded strings:".to_string());
            for d in &result.decoded_strings {
                output.push(format!("  {}('{}') -> '{}'", d.function, d.input, d.output));
            }
        }

        if !result.api_calls.is_empty() {
            output.push("API calls traced:".to_string());
            for c in &result.api_calls {
                let args_str = c.arguments.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
                output.push(format!("  {}({})", c.function, args_str));
            }
        }

        if let Some(ref val) = result.final_value {
            output.push(format!("Final value: {}", val));
        }

        if let Some(ref err) = result.error {
            output.push(format!("Error: {}", err));
        }

        if output.is_empty() {
            Ok("No output — code executed without producing observable results.".to_string())
        } else {
            Ok(output.join("\n"))
        }
    }
}

// ── SubmitVerdict tool ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SubmitVerdictArgs {
    pub action: String,
    pub new_severity: Option<String>,
    pub reasoning: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SubmitVerdictTool;

impl Tool for SubmitVerdictTool {
    const NAME: &'static str = "submit_verdict";
    type Error = ReviewToolError;
    type Args = SubmitVerdictArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "submit_verdict".to_string(),
            description: "Submit your final verdict on this finding. Call this once you have enough evidence.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["confirm", "downgrade", "dismiss"],
                        "description": "confirm = keep finding as-is, downgrade = lower severity, dismiss = remove finding (false positive)"
                    },
                    "new_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "New severity level (only required when action is 'downgrade')"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Explanation of your verdict — what you investigated and what you found"
                    }
                },
                "required": ["action", "reasoning"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // The verdict is returned as the tool output, which becomes part of the
        // conversation. The review_agent module reads the final agent response
        // to extract the verdict.
        Ok(serde_json::to_string(&serde_json::json!({
            "action": args.action,
            "new_severity": args.new_severity,
            "reasoning": args.reasoning,
        })).unwrap())
    }
}
```

**Step 4: Register the module**

In `src/llm/mod.rs`, add:

```rust
pub mod tools;
```

**Step 5: Run tests to verify they pass**

Run: `cargo test tools::tests`
Expected: PASS

**Step 6: Run clippy**

Run: `cargo clippy`
Expected: No warnings.

**Step 7: Commit**

```bash
git add src/llm/tools.rs src/llm/mod.rs
git commit -m "feat(llm): implement review agent tools"
```

---

### Task 4: Implement review agent orchestration

**Files:**
- Create: `src/llm/review_agent.rs`
- Modify: `src/llm/mod.rs`

**Step 1: Write a test for verdict parsing**

At the bottom of `src/llm/review_agent.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Severity};

    #[test]
    fn test_parse_verdict_confirm() {
        let json = r#"{"action": "confirm", "reasoning": "this is real"}"#;
        let verdict = parse_verdict(json).unwrap();
        assert!(matches!(verdict, Verdict::Confirm { .. }));
    }

    #[test]
    fn test_parse_verdict_downgrade() {
        let json = r#"{"action": "downgrade", "new_severity": "info", "reasoning": "harmless"}"#;
        let verdict = parse_verdict(json).unwrap();
        match verdict {
            Verdict::Downgrade { new_severity, reasoning } => {
                assert!(matches!(new_severity, Severity::Info));
                assert_eq!(reasoning, "harmless");
            }
            _ => panic!("Expected Downgrade"),
        }
    }

    #[test]
    fn test_parse_verdict_dismiss() {
        let json = r#"{"action": "dismiss", "reasoning": "false positive"}"#;
        let verdict = parse_verdict(json).unwrap();
        assert!(matches!(verdict, Verdict::Dismiss { .. }));
    }

    #[test]
    fn test_apply_verdict_confirm() {
        let finding = Finding::new(Severity::Medium, Category::Obfuscation, "test");
        let verdict = Verdict::Confirm { reasoning: "confirmed".into() };
        let result = apply_verdict(finding, verdict);
        assert!(result.is_some());
        let f = result.unwrap();
        assert!(matches!(f.severity, Severity::Medium));
        assert_eq!(f.review_reasoning.as_deref(), Some("confirmed"));
    }

    #[test]
    fn test_apply_verdict_downgrade() {
        let finding = Finding::new(Severity::Medium, Category::Obfuscation, "test");
        let verdict = Verdict::Downgrade { new_severity: Severity::Info, reasoning: "benign".into() };
        let result = apply_verdict(finding, verdict);
        assert!(result.is_some());
        let f = result.unwrap();
        assert!(matches!(f.severity, Severity::Info));
        assert!(f.review_reasoning.as_deref().unwrap().contains("benign"));
    }

    #[test]
    fn test_apply_verdict_dismiss() {
        let finding = Finding::new(Severity::Medium, Category::Obfuscation, "test");
        let verdict = Verdict::Dismiss { reasoning: "false positive".into() };
        let result = apply_verdict(finding, verdict);
        assert!(result.is_none());
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test review_agent::tests`
Expected: FAIL — module doesn't exist.

**Step 3: Implement the review agent**

Create `src/llm/review_agent.rs`:

```rust
use anyhow::Result;
use rig::completion::Prompt;

use super::LlmClient;
use super::tools::{
    ExtensionContext, ReadFileTool, RunSandboxTool, SearchCodeTool, SubmitVerdictTool,
};
use crate::models::{Extension, ExtensionFile, FileType, Finding, Severity};

use std::path::PathBuf;
use std::sync::Arc;

/// Maximum number of tool-call turns the agent can make per finding
const MAX_TOOL_CALLS: usize = 50;

/// Default models for each provider (can use cheaper models for review)
const DEFAULT_OPENAI_MODEL: &str = "gpt-4o-mini";
const DEFAULT_ANTHROPIC_MODEL: &str = "claude-3-haiku-20240307";
const DEFAULT_GEMINI_MODEL: &str = "gemini-3-flash-preview";

#[derive(Debug)]
pub enum Verdict {
    Confirm { reasoning: String },
    Downgrade { new_severity: Severity, reasoning: String },
    Dismiss { reasoning: String },
}

pub fn parse_verdict(text: &str) -> Option<Verdict> {
    // Try to find JSON in the response — the submit_verdict tool returns JSON
    let json_str = extract_json(text)?;
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;

    let action = val.get("action")?.as_str()?;
    let reasoning = val.get("reasoning")?.as_str()?.to_string();

    match action {
        "confirm" => Some(Verdict::Confirm { reasoning }),
        "downgrade" => {
            let sev_str = val.get("new_severity").and_then(|v| v.as_str()).unwrap_or("info");
            let new_severity = parse_severity(sev_str);
            Some(Verdict::Downgrade { new_severity, reasoning })
        }
        "dismiss" => Some(Verdict::Dismiss { reasoning }),
        _ => None,
    }
}

fn extract_json(text: &str) -> Option<&str> {
    // First try the whole text as JSON
    if text.trim().starts_with('{') {
        return Some(text.trim());
    }
    // Look for JSON embedded in the response
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end > start {
        Some(&text[start..=end])
    } else {
        None
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

pub fn apply_verdict(mut finding: Finding, verdict: Verdict) -> Option<Finding> {
    match verdict {
        Verdict::Confirm { reasoning } => {
            finding.review_reasoning = Some(reasoning);
            Some(finding)
        }
        Verdict::Downgrade { new_severity, reasoning } => {
            let old_severity = finding.severity.as_str().to_string();
            finding.severity = new_severity;
            finding.review_reasoning = Some(format!(
                "Downgraded from {}. {}",
                old_severity, reasoning
            ));
            Some(finding)
        }
        Verdict::Dismiss { reasoning } => {
            tracing::debug!(
                "Finding dismissed: '{}' — {}",
                finding.title,
                reasoning
            );
            None
        }
    }
}

fn build_system_prompt(extension: &Extension) -> String {
    let file_list: Vec<String> = extension
        .files
        .iter()
        .filter(|f| matches!(f.file_type, FileType::JavaScript | FileType::Json | FileType::Html))
        .map(|f| format!("  {}", f.path.display()))
        .collect();

    format!(
        r#"You are a security analyst reviewing a finding from static analysis of a browser extension. Your job is to INVESTIGATE whether this finding represents a real security concern or a false positive.

Static analysis flagged this code but may be wrong. Common false positives include:
- String.fromCharCode() used for legitimate character conversion
- atob() used for non-sensitive data decoding
- eval() in a build tool or test harness
- fetch() calls to the extension's own API
- chrome.tabs.query used for normal tab management

Use your tools to trace where values come from, read surrounding code, and understand the actual intent. When you have enough evidence, call submit_verdict.

Available tools:
- read_file: Read any file from the extension
- search_code: Search all files for a text pattern
- run_sandbox: Execute JavaScript in an isolated sandbox to see what it does
- submit_verdict: Deliver your final judgment (confirm/downgrade/dismiss)

Extension files:
{}

IMPORTANT: You MUST call submit_verdict when you have reached a conclusion. Do not just describe your findings in text."#,
        file_list.join("\n")
    )
}

fn build_finding_prompt(finding: &Finding) -> String {
    let location = finding
        .location
        .as_ref()
        .map(|l| l.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let snippet = finding
        .code_snippet
        .as_deref()
        .unwrap_or("(no snippet available)");

    format!(
        r#"Review this finding:

Title: {}
Severity: {}
Category: {}
Description: {}
Location: {}

Code snippet:
```
{}
```

Investigate whether this is a genuine security concern or a false positive. Read the surrounding code, trace where parameters come from, and run the sandbox if you need to see runtime behavior. Then call submit_verdict with your judgment."#,
        finding.title,
        finding.severity.as_str(),
        finding.category.as_str(),
        finding.description,
        location,
        snippet,
    )
}

/// Review all findings using the agentic review loop
pub async fn review_findings(
    client: &LlmClient,
    extension: &Extension,
    findings: Vec<Finding>,
    model: Option<&str>,
) -> Result<Vec<Finding>> {
    let context = ExtensionContext {
        files: Arc::new(extension.files.clone()),
        extract_path: Arc::new(
            extension.extract_path.clone().unwrap_or_else(|| PathBuf::from(".")),
        ),
    };

    let system_prompt = build_system_prompt(extension);
    let mut reviewed = Vec::new();

    for (i, finding) in findings.into_iter().enumerate() {
        tracing::info!("Reviewing finding {}: {}", i + 1, finding.title);

        let finding_prompt = build_finding_prompt(&finding);

        match review_single_finding(client, &context, &system_prompt, &finding_prompt, model).await
        {
            Ok(response) => {
                if let Some(verdict) = parse_verdict(&response) {
                    if let Some(reviewed_finding) = apply_verdict(finding, verdict) {
                        reviewed.push(reviewed_finding);
                    }
                    // If apply_verdict returns None, finding was dismissed
                } else {
                    // Could not parse verdict — keep finding as-is (fail-safe)
                    tracing::warn!("Could not parse verdict for finding '{}', keeping as-is", finding.title);
                    reviewed.push(finding);
                }
            }
            Err(e) => {
                // On error, keep finding as-is (fail-safe)
                tracing::warn!("Review failed for '{}': {}, keeping as-is", finding.title, e);
                reviewed.push(finding);
            }
        }
    }

    Ok(reviewed)
}

/// Review a single finding using the agent with tools
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
```

**Step 4: Register the module in mod.rs**

In `src/llm/mod.rs`, add:

```rust
pub mod review_agent;
pub use review_agent::review_findings;
```

**Step 5: Run tests**

Run: `cargo test review_agent::tests`
Expected: PASS

**Step 6: Run clippy**

Run: `cargo clippy`
Expected: No warnings.

**Step 7: Commit**

```bash
git add src/llm/review_agent.rs src/llm/mod.rs
git commit -m "feat(llm): implement agentic finding review loop"
```

---

### Task 5: Integrate review into main pipeline

**Files:**
- Modify: `src/main.rs`

**Step 1: Add the review step**

In `src/main.rs`, in the `analyze_single` function, after static analysis and before LLM analysis, add the review step. Find this block:

```rust
// Run LLM analysis if enabled
if !args.no_llm {
    println!("{}", "Running LLM analysis...".bright_black());
```

Insert before it:

```rust
// Review static findings with LLM agent
if !args.no_llm {
    println!("{}", "Reviewing findings with LLM agent...".bright_black());

    match args.llm.parse::<LlmProvider>() {
        Ok(provider) => match create_provider(&provider) {
            Ok(client) => {
                match extanalyzer::llm::review_findings(
                    &client,
                    &extension,
                    result.findings,
                    args.model.as_deref(),
                )
                .await
                {
                    Ok(reviewed) => {
                        let original_count = result.findings.len();
                        result.findings = reviewed;
                        let dismissed = original_count.saturating_sub(result.findings.len());
                        if dismissed > 0 {
                            println!(
                                "{}",
                                format!("  {} findings dismissed as false positives", dismissed)
                                    .bright_black()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("{} Finding review failed: {}", "Warning:".yellow(), e);
                    }
                }
            }
            Err(e) => {
                eprintln!("{} Could not create LLM client: {}", "Warning:".yellow(), e);
            }
        },
        Err(e) => {
            eprintln!("{} {}", "Warning:".yellow(), e);
        }
    }
}
```

Note: This duplicates the provider creation. To avoid that, refactor the provider creation to happen once before both review and LLM analysis. Move the `parse/create_provider` outside and reuse the client. The exact refactoring:

Replace the current `if !args.no_llm { ... }` block with:

```rust
if !args.no_llm {
    match args.llm.parse::<LlmProvider>() {
        Ok(provider) => match create_provider(&provider) {
            Ok(client) => {
                // Step 1: Review static findings
                println!("{}", "Reviewing findings with LLM agent...".bright_black());
                match extanalyzer::llm::review_findings(
                    &client,
                    &extension,
                    result.findings,
                    args.model.as_deref(),
                )
                .await
                {
                    Ok(reviewed) => {
                        result.findings = reviewed;
                    }
                    Err(e) => {
                        eprintln!("{} Finding review failed: {}", "Warning:".yellow(), e);
                    }
                }

                // Step 2: Run remaining LLM analysis tasks
                println!("{}", "Running LLM analysis...".bright_black());
                let tasks = vec![
                    AnalysisTask::ManifestReview,
                    AnalysisTask::ScriptAnalysis,
                    AnalysisTask::EndpointAnalysis,
                    AnalysisTask::DarkPatternReview,
                    AnalysisTask::FinalSummary,
                ];

                match analyze_with_llm(
                    &client,
                    &extension,
                    &result.findings,
                    &result.endpoints,
                    tasks,
                    args.model.as_deref(),
                )
                .await
                {
                    Ok(llm_result) => {
                        result.findings.extend(llm_result.findings);
                        result.llm_summary = llm_result.summary;
                    }
                    Err(e) => {
                        eprintln!("{} LLM analysis failed: {}", "Warning:".yellow(), e);
                    }
                }
            }
            Err(e) => {
                eprintln!("{} Could not create LLM client: {}", "Warning:".yellow(), e);
            }
        },
        Err(e) => {
            eprintln!("{} {}", "Warning:".yellow(), e);
        }
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check`
Expected: Compiles.

**Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat: integrate agentic finding review into main pipeline"
```

---

### Task 6: Remove obfuscation section from ScriptAnalysis prompt

**Files:**
- Modify: `src/llm/agents.rs`

**Step 1: Remove the obfuscation prompt section**

In `src/llm/agents.rs`, in `build_script_prompt`, remove the block that collects obfuscation findings and creates the "STATIC ANALYSIS DETECTED OBFUSCATION" section. Specifically remove:

1. The `obfuscation_snippets` collection (the `let obfuscation_snippets: Vec<String> = ...` block)
2. The `obfuscation_section` variable
3. The `{}` placeholder for `obfuscation_section` in the format string

Also remove the "DEOBFUSCATE:" instruction from the prompt text and from `parse_findings`.

The `build_script_prompt` function should no longer reference `static_findings` at all — change its signature to remove that parameter:

```rust
fn build_script_prompt(extension: &Extension) -> String {
```

And update the call site in `build_prompt` to match.

Also remove the DEOBFUSCATE handling block in `parse_findings` (the `for line in response.lines()` block that checks for `"DEOBFUSCATE:"`).

**Step 2: Verify it compiles**

Run: `cargo check`
Expected: Compiles.

**Step 3: Run existing tests**

Run: `cargo test`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add src/llm/agents.rs
git commit -m "refactor(llm): remove obfuscation section from script prompt"
```

---

### Task 7: Display review reasoning in terminal output

**Files:**
- Modify: `src/output/terminal.rs`

**Step 1: Add review reasoning display**

In `src/output/terminal.rs`, in the `print_finding` function, after the description printing block and before the snippet printing, add:

```rust
if let Some(ref reasoning) = finding.review_reasoning {
    for line in textwrap::wrap(reasoning, 56) {
        println!("            {} {}", "Agent:".bright_blue(), line);
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check`
Expected: Compiles.

**Step 3: Commit**

```bash
git add src/output/terminal.rs
git commit -m "feat(output): display agent review reasoning in findings"
```

---

### Task 8: Integration test with mock extension

**Files:**
- Create: `tests/review_agent_tests.rs`

**Step 1: Write integration test for verdict parsing and application**

```rust
use extanalyzer::models::{Category, Finding, Severity};
use extanalyzer::llm::review_agent::{apply_verdict, parse_verdict, Verdict};

#[test]
fn test_full_verdict_flow_confirm() {
    let finding = Finding::new(
        Severity::Medium,
        Category::Obfuscation,
        "String.fromCharCode() obfuscation detected",
    )
    .with_description("String.fromCharCode() is commonly used to obfuscate malicious code");

    let response = r#"{"action": "confirm", "reasoning": "This code constructs a URL character by character from numeric codes, likely to avoid URL detection by static analysis."}"#;
    let verdict = parse_verdict(response).unwrap();
    let result = apply_verdict(finding, verdict);

    assert!(result.is_some());
    let f = result.unwrap();
    assert!(matches!(f.severity, Severity::Medium));
    assert!(f.review_reasoning.unwrap().contains("URL detection"));
}

#[test]
fn test_full_verdict_flow_downgrade() {
    let finding = Finding::new(
        Severity::Medium,
        Category::Obfuscation,
        "String.fromCharCode() obfuscation detected",
    )
    .with_description("String.fromCharCode() is commonly used to obfuscate malicious code");

    let response = r#"{"action": "downgrade", "new_severity": "info", "reasoning": "This is a standard UTF-8 byte-to-character conversion used in the i18n module."}"#;
    let verdict = parse_verdict(response).unwrap();
    let result = apply_verdict(finding, verdict);

    assert!(result.is_some());
    let f = result.unwrap();
    assert!(matches!(f.severity, Severity::Info));
    assert!(f.review_reasoning.unwrap().contains("Downgraded from MEDIUM"));
}

#[test]
fn test_full_verdict_flow_dismiss() {
    let finding = Finding::new(
        Severity::Medium,
        Category::Obfuscation,
        "String.fromCharCode() obfuscation detected",
    );

    let response = r#"{"action": "dismiss", "reasoning": "False positive: fromCharCode(0xff) is used to create a single byte for binary protocol handling."}"#;
    let verdict = parse_verdict(response).unwrap();
    let result = apply_verdict(finding, verdict);

    assert!(result.is_none());
}

#[test]
fn test_verdict_parsing_from_agent_response_with_surrounding_text() {
    // The agent may include text around the JSON
    let response = r#"After investigating, I found this is benign. {"action": "dismiss", "reasoning": "False positive"} That concludes my review."#;
    let verdict = parse_verdict(response);
    assert!(verdict.is_some());
    assert!(matches!(verdict.unwrap(), Verdict::Dismiss { .. }));
}

#[test]
fn test_verdict_parsing_fails_gracefully_on_garbage() {
    let response = "I couldn't determine the issue. Let me investigate more.";
    let verdict = parse_verdict(response);
    assert!(verdict.is_none());
}
```

**Step 2: Run tests**

Run: `cargo test --test review_agent_tests`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/review_agent_tests.rs
git commit -m "test: add integration tests for agentic finding review"
```

---

### Task 9: Final verification

**Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass.

**Step 2: Run clippy**

Run: `cargo clippy`
Expected: No warnings.

**Step 3: Build release**

Run: `cargo build --release`
Expected: Compiles successfully.

**Step 4: Manual smoke test (optional)**

Run with a real extension and LLM:
```bash
cargo run -- --llm openai nkbihfbeogaeaoehlefnkodbefgpgknn
```
Expected: See "Reviewing findings with LLM agent..." output, findings should show "Agent:" reasoning lines.
