use std::path::PathBuf;
use std::sync::Arc;

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};

use crate::models::ExtensionFile;
use crate::sandbox::execute_snippet;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Shared context giving tools access to extension files and extract path.
#[derive(Clone)]
pub struct ExtensionContext {
    pub files: Arc<Vec<ExtensionFile>>,
    pub extract_path: Arc<PathBuf>,
}

/// Error type shared by all review-agent tools.
#[derive(Debug, thiserror::Error)]
#[error("Tool error: {0}")]
pub struct ReviewToolError(pub String);

/// Maximum file content size returned by ReadFileTool (50 KB).
const MAX_FILE_SIZE: usize = 50 * 1024;

/// Maximum number of search results returned by SearchCodeTool.
const MAX_SEARCH_RESULTS: usize = 50;

// ---------------------------------------------------------------------------
// ReadFileTool
// ---------------------------------------------------------------------------

/// Reads a file from the extension by relative path.
pub struct ReadFileTool {
    context: ExtensionContext,
}

impl ReadFileTool {
    pub fn new(context: ExtensionContext) -> Self {
        Self { context }
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct ReadFileArgs {
    /// Relative path of the file within the extension (e.g. "background.js").
    pub path: String,
}

impl Tool for ReadFileTool {
    const NAME: &'static str = "read_file";

    type Error = ReviewToolError;
    type Args = ReadFileArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Read the contents of a file from the extension by its relative path. \
                           Returns file content (truncated to 50 KB) or an error message if the \
                           file is not found."
                .to_string(),
            parameters: serde_json::to_value(schema_for!(ReadFileArgs))
                .expect("schema serialization should not fail"),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let target = PathBuf::from(&args.path);

        // First try to find the file among pre-loaded extension files.
        for file in self.context.files.iter() {
            if file.path == target
                && let Some(ref content) = file.content
            {
                return Ok(truncate(content, MAX_FILE_SIZE));
            }
        }

        // Fall back to reading from the extract directory on disk.
        let full_path = self.context.extract_path.join(&target);
        match std::fs::read_to_string(&full_path) {
            Ok(content) => Ok(truncate(&content, MAX_FILE_SIZE)),
            Err(_) => Ok(format!("File not found: {}", args.path)),
        }
    }
}

/// Truncate a string to at most `max_bytes` bytes on a char boundary.
fn truncate(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        s.to_string()
    } else {
        let mut end = max_bytes;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}... [truncated]", &s[..end])
    }
}

// ---------------------------------------------------------------------------
// SearchCodeTool
// ---------------------------------------------------------------------------

/// Searches all extension files for a substring pattern.
pub struct SearchCodeTool {
    context: ExtensionContext,
}

impl SearchCodeTool {
    pub fn new(context: ExtensionContext) -> Self {
        Self { context }
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct SearchCodeArgs {
    /// Substring pattern to search for in all extension source files.
    pub pattern: String,
}

impl Tool for SearchCodeTool {
    const NAME: &'static str = "search_code";

    type Error = ReviewToolError;
    type Args = SearchCodeArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Search all extension files for a substring pattern. Returns matching \
                           lines in the format 'filepath:line_num: line_content'. Results are \
                           capped at 50 matches."
                .to_string(),
            parameters: serde_json::to_value(schema_for!(SearchCodeArgs))
                .expect("schema serialization should not fail"),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let mut results: Vec<String> = Vec::new();

        for file in self.context.files.iter() {
            if let Some(ref content) = file.content {
                for (line_num, line) in content.lines().enumerate() {
                    if line.contains(&args.pattern) {
                        results.push(format!(
                            "{}:{}: {}",
                            file.path.display(),
                            line_num + 1,
                            line
                        ));
                        if results.len() >= MAX_SEARCH_RESULTS {
                            break;
                        }
                    }
                }
            }
            if results.len() >= MAX_SEARCH_RESULTS {
                break;
            }
        }

        if results.is_empty() {
            Ok(format!("No matches found for pattern: {}", args.pattern))
        } else {
            Ok(results.join("\n"))
        }
    }
}

// ---------------------------------------------------------------------------
// RunSandboxTool
// ---------------------------------------------------------------------------

/// Runs a JavaScript snippet in the QuickJS sandbox for deobfuscation.
pub struct RunSandboxTool;

#[derive(Deserialize, JsonSchema)]
pub struct RunSandboxArgs {
    /// JavaScript code to execute in the isolated QuickJS sandbox.
    pub code: String,
}

impl Tool for RunSandboxTool {
    const NAME: &'static str = "run_sandbox";

    type Error = ReviewToolError;
    type Args = RunSandboxArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Execute a JavaScript snippet in an isolated QuickJS sandbox. Useful \
                           for deobfuscating code (e.g. String.fromCharCode, atob). Returns \
                           decoded strings, traced API calls, and the final expression value."
                .to_string(),
            parameters: serde_json::to_value(schema_for!(RunSandboxArgs))
                .expect("schema serialization should not fail"),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let result = execute_snippet(&args.code, 2000);

        let mut output = String::new();

        // Decoded strings
        if !result.decoded_strings.is_empty() {
            output.push_str("Decoded strings:\n");
            for d in &result.decoded_strings {
                output.push_str(&format!(
                    "  {}('{}') -> '{}'\n",
                    d.function, d.input, d.output
                ));
            }
        }

        // API calls
        if !result.api_calls.is_empty() {
            output.push_str("API calls:\n");
            for c in &result.api_calls {
                let args_str: Vec<String> = c.arguments.iter().map(|a| a.to_string()).collect();
                output.push_str(&format!("  {}({})\n", c.function, args_str.join(", ")));
            }
        }

        // Final value
        if let Some(ref val) = result.final_value {
            output.push_str(&format!("Final value: {}\n", val));
        }

        // Error
        if let Some(ref err) = result.error {
            output.push_str(&format!("Error: {}\n", err));
        }

        if output.is_empty() {
            output.push_str("No output produced.");
        }

        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// SubmitVerdictTool
// ---------------------------------------------------------------------------

/// Terminal tool the agent uses to submit its final verdict on a finding.
pub struct SubmitVerdictTool;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SubmitVerdictArgs {
    /// Action to take: "confirm", "adjust_severity", or "dismiss".
    pub action: String,
    /// New severity level if action is "adjust_severity" (e.g. "critical", "high", "medium", "low", "info").
    pub new_severity: Option<String>,
    /// Reasoning behind the verdict.
    pub reasoning: String,
}

impl Tool for SubmitVerdictTool {
    const NAME: &'static str = "submit_verdict";

    type Error = ReviewToolError;
    type Args = SubmitVerdictArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Submit the final verdict for a finding review. Use action 'confirm' to \
                           keep the finding as-is, 'adjust_severity' to change the severity level \
                           (provide new_severity), or 'dismiss' to mark the finding as a false \
                           positive. Always include reasoning."
                .to_string(),
            parameters: serde_json::to_value(schema_for!(SubmitVerdictArgs))
                .expect("schema serialization should not fail"),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        serde_json::to_string(&args).map_err(|e| ReviewToolError(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::FileType;
    use std::path::PathBuf;

    fn make_context() -> ExtensionContext {
        let files = vec![
            ExtensionFile {
                path: PathBuf::from("background.js"),
                content: Some("console.log('hello');\nfetch('https://example.com');\n".to_string()),
                file_type: FileType::JavaScript,
            },
            ExtensionFile {
                path: PathBuf::from("manifest.json"),
                content: Some(r#"{"name":"test","version":"1.0"}"#.to_string()),
                file_type: FileType::Json,
            },
        ];
        ExtensionContext {
            files: Arc::new(files),
            extract_path: Arc::new(PathBuf::from("/tmp/ext_test")),
        }
    }

    // ---- Argument deserialization tests ----

    #[test]
    fn test_read_file_args_deserialize() {
        let json = r#"{"path": "background.js"}"#;
        let args: ReadFileArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.path, "background.js");
    }

    #[test]
    fn test_search_code_args_deserialize() {
        let json = r#"{"pattern": "fetch"}"#;
        let args: SearchCodeArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.pattern, "fetch");
    }

    #[test]
    fn test_run_sandbox_args_deserialize() {
        let json = r#"{"code": "1 + 2"}"#;
        let args: RunSandboxArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.code, "1 + 2");
    }

    #[test]
    fn test_submit_verdict_args_deserialize() {
        let json = r#"{"action": "confirm", "reasoning": "Looks suspicious"}"#;
        let args: SubmitVerdictArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.action, "confirm");
        assert!(args.new_severity.is_none());
        assert_eq!(args.reasoning, "Looks suspicious");
    }

    #[test]
    fn test_submit_verdict_args_with_severity() {
        let json =
            r#"{"action": "adjust_severity", "new_severity": "critical", "reasoning": "Very bad"}"#;
        let args: SubmitVerdictArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.action, "adjust_severity");
        assert_eq!(args.new_severity.as_deref(), Some("critical"));
        assert_eq!(args.reasoning, "Very bad");
    }

    // ---- ReadFileTool tests ----

    #[tokio::test]
    async fn test_read_file_found() {
        let ctx = make_context();
        let tool = ReadFileTool::new(ctx);
        let result = tool
            .call(ReadFileArgs {
                path: "background.js".to_string(),
            })
            .await
            .unwrap();
        assert!(result.contains("console.log"));
    }

    #[tokio::test]
    async fn test_read_file_not_found() {
        let ctx = make_context();
        let tool = ReadFileTool::new(ctx);
        let result = tool
            .call(ReadFileArgs {
                path: "nonexistent.js".to_string(),
            })
            .await
            .unwrap();
        assert!(result.starts_with("File not found:"));
    }

    #[tokio::test]
    async fn test_read_file_truncation() {
        let big_content = "x".repeat(MAX_FILE_SIZE + 100);
        let files = vec![ExtensionFile {
            path: PathBuf::from("big.js"),
            content: Some(big_content),
            file_type: FileType::JavaScript,
        }];
        let ctx = ExtensionContext {
            files: Arc::new(files),
            extract_path: Arc::new(PathBuf::from("/tmp")),
        };
        let tool = ReadFileTool::new(ctx);
        let result = tool
            .call(ReadFileArgs {
                path: "big.js".to_string(),
            })
            .await
            .unwrap();
        assert!(result.ends_with("... [truncated]"));
        assert!(result.len() <= MAX_FILE_SIZE + 20); // some slack for suffix
    }

    // ---- SearchCodeTool tests ----

    #[tokio::test]
    async fn test_search_code_found() {
        let ctx = make_context();
        let tool = SearchCodeTool::new(ctx);
        let result = tool
            .call(SearchCodeArgs {
                pattern: "fetch".to_string(),
            })
            .await
            .unwrap();
        assert!(result.contains("background.js:2:"));
        assert!(result.contains("fetch"));
    }

    #[tokio::test]
    async fn test_search_code_not_found() {
        let ctx = make_context();
        let tool = SearchCodeTool::new(ctx);
        let result = tool
            .call(SearchCodeArgs {
                pattern: "cryptocurrency_miner".to_string(),
            })
            .await
            .unwrap();
        assert!(result.starts_with("No matches found"));
    }

    #[tokio::test]
    async fn test_search_code_capped() {
        // Create a file with many matching lines.
        let content = (0..100)
            .map(|i| format!("line {} match_me", i))
            .collect::<Vec<_>>()
            .join("\n");
        let files = vec![ExtensionFile {
            path: PathBuf::from("many.js"),
            content: Some(content),
            file_type: FileType::JavaScript,
        }];
        let ctx = ExtensionContext {
            files: Arc::new(files),
            extract_path: Arc::new(PathBuf::from("/tmp")),
        };
        let tool = SearchCodeTool::new(ctx);
        let result = tool
            .call(SearchCodeArgs {
                pattern: "match_me".to_string(),
            })
            .await
            .unwrap();
        let line_count = result.lines().count();
        assert_eq!(line_count, MAX_SEARCH_RESULTS);
    }

    // ---- RunSandboxTool tests ----

    #[tokio::test]
    async fn test_run_sandbox_basic() {
        let tool = RunSandboxTool;
        let result = tool
            .call(RunSandboxArgs {
                code: "1 + 2".to_string(),
            })
            .await
            .unwrap();
        assert!(result.contains("Final value: 3"));
    }

    #[tokio::test]
    async fn test_run_sandbox_decode() {
        let tool = RunSandboxTool;
        let result = tool
            .call(RunSandboxArgs {
                code: "atob('aGVsbG8=')".to_string(),
            })
            .await
            .unwrap();
        assert!(result.contains("hello"));
    }

    // ---- SubmitVerdictTool tests ----

    #[tokio::test]
    async fn test_submit_verdict_returns_json() {
        let tool = SubmitVerdictTool;
        let result = tool
            .call(SubmitVerdictArgs {
                action: "dismiss".to_string(),
                new_severity: None,
                reasoning: "False positive".to_string(),
            })
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["action"], "dismiss");
        assert_eq!(parsed["reasoning"], "False positive");
    }

    // ---- ToolDefinition tests ----

    #[tokio::test]
    async fn test_read_file_definition() {
        let ctx = make_context();
        let tool = ReadFileTool::new(ctx);
        let def = tool.definition(String::new()).await;
        assert_eq!(def.name, "read_file");
        assert!(!def.description.is_empty());
        assert!(def.parameters.is_object());
    }

    #[tokio::test]
    async fn test_search_code_definition() {
        let ctx = make_context();
        let tool = SearchCodeTool::new(ctx);
        let def = tool.definition(String::new()).await;
        assert_eq!(def.name, "search_code");
        assert!(def.parameters.is_object());
    }

    #[tokio::test]
    async fn test_run_sandbox_definition() {
        let tool = RunSandboxTool;
        let def = tool.definition(String::new()).await;
        assert_eq!(def.name, "run_sandbox");
        assert!(def.parameters.is_object());
    }

    #[tokio::test]
    async fn test_submit_verdict_definition() {
        let tool = SubmitVerdictTool;
        let def = tool.definition(String::new()).await;
        assert_eq!(def.name, "submit_verdict");
        assert!(def.parameters.is_object());
    }
}
