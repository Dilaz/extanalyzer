//! Run extracted code snippets in sandbox to trace actual fetch arguments

use crate::models::{DataSource, Endpoint, ExtensionFile, FileType, SandboxTrace, TracedFetch};
use crate::sandbox::{execute_snippet, SandboxResult};
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
            if matches!(f.file_type, FileType::JavaScript) {
                let content_len = f.content.as_ref().map(|c| c.len()).unwrap_or(0);
                if content_len <= config.max_file_size && content_len > 0 {
                    f.content.as_ref().map(|c| (f.path.clone(), c.clone()))
                } else {
                    None
                }
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

    // Check for async function declaration: async function name(...)
    if code.starts_with("async function ")
        && let Some(name_start) = code.find("function ")
        && let Some(name_end) = code[name_start + 9..].find('(')
    {
        let name = code[name_start + 9..name_start + 9 + name_end].trim();
        if !name.is_empty() {
            let params = count_parameters(code);
            let args = generate_dummy_args(params);
            return format!("{}\n{}({});", code, name, args);
        }
    }

    // Check for function declaration: function name(...)
    if code.starts_with("function ")
        && let Some(name_end) = code.find('(')
    {
        let name = code[9..name_end].trim();
        if !name.is_empty() {
            // Count parameters to generate dummy args
            let params = count_parameters(code);
            let args = generate_dummy_args(params);
            return format!("{}\n{}({});", code, name, args);
        }
    }

    // Check for arrow function assigned to const/let: const name = (...) =>
    if (code.starts_with("const ") || code.starts_with("let "))
        && let Some(eq_pos) = code.find('=')
    {
        let name_with_keyword = &code[..eq_pos];
        let name = name_with_keyword
            .trim()
            .trim_start_matches("const ")
            .trim_start_matches("let ")
            .trim();
        if !name.is_empty() && code[eq_pos..].contains("=>") {
            let params = count_parameters(code);
            let args = generate_dummy_args(params);
            return format!("{}\n{}({});", code, name, args);
        }
    }

    // Check for anonymous arrow function: async () => {...} or () => {...}
    // The code may be indented, so check trimmed version
    let trimmed = code.trim();
    if (trimmed.starts_with("async () =>")
        || trimmed.starts_with("async() =>")
        || trimmed.starts_with("() =>"))
        && !trimmed.starts_with("const ")
        && !trimmed.starts_with("let ")
    {
        // Wrap in IIFE - but need to provide mock request object for handler callbacks
        return format!(
            "const request = {{ assetId: 12345, assetType: 'gamepass', userId: 99999, items: [] }};\n({})();",
            trimmed
        );
    }

    code.to_string()
}

/// Count function parameters (simple heuristic)
fn count_parameters(code: &str) -> usize {
    if let Some(start) = code.find('(')
        && let Some(end) = code[start..].find(')')
    {
        let params = &code[start + 1..start + end];
        if params.trim().is_empty() {
            return 0;
        }
        return params.split(',').count();
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
            let url = c
                .arguments
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let (method, body) = if let Some(opts) = c.arguments.get(1) {
                let method = opts.get("method").and_then(|v| v.as_str()).map(String::from);
                let body = opts.get("body").map(|v| v.to_string());
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
    use crate::sandbox::ApiCall;

    #[test]
    fn test_maybe_add_invocation_function() {
        let code = "function sendData(x) { fetch(x); }";
        let result = maybe_add_invocation(code);
        assert!(result.contains("sendData(\"test\");"));
    }

    #[test]
    fn test_maybe_add_invocation_async_function() {
        let code = "async function sendData(x) { await fetch(x); }";
        let result = maybe_add_invocation(code);
        assert!(result.contains("sendData(\"test\");"));
    }

    #[test]
    fn test_maybe_add_invocation_arrow() {
        let code = "const submit = (a, b) => { fetch(a); }";
        let result = maybe_add_invocation(code);
        assert!(result.contains("submit(\"test\", 12345);"));
        // Ensure no corrupted name like "t submit(" from off-by-one error
        assert!(!result.contains("t submit("));
    }

    #[test]
    fn test_maybe_add_invocation_no_params() {
        let code = "function getData() { fetch('/api'); }";
        let result = maybe_add_invocation(code);
        assert!(result.contains("getData();"));
    }

    #[test]
    fn test_maybe_add_invocation_anonymous_arrow() {
        let code = "async () => { await fetch('/api'); }";
        let result = maybe_add_invocation(code);
        assert!(result.contains("const request ="));
        // IIFE format: (async () => {...})();
        assert!(result.contains("})();"));
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
