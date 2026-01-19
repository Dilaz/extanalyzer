use serde::{Deserialize, Serialize};

/// Result from sandbox execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxResult {
    /// Strings that were decoded (atob, fromCharCode, etc.)
    pub decoded_strings: Vec<DecodedString>,
    /// API calls that were attempted (fetch, chrome.*, etc.)
    pub api_calls: Vec<ApiCall>,
    /// Final value of the last expression, if any
    pub final_value: Option<String>,
    /// Error message if execution failed
    pub error: Option<String>,
}

/// A decoded string from obfuscation functions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedString {
    /// Function that was called (atob, fromCharCode, etc.)
    pub function: String,
    /// The encoded input
    pub input: String,
    /// The decoded output
    pub output: String,
}

/// An API call that was traced
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiCall {
    /// Full function path (e.g., "chrome.cookies.getAll", "fetch")
    pub function: String,
    /// Arguments passed to the function
    pub arguments: Vec<serde_json::Value>,
}

impl SandboxResult {
    pub fn with_error(error: impl Into<String>) -> Self {
        Self {
            error: Some(error.into()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_result_default() {
        let result = SandboxResult::default();
        assert!(result.decoded_strings.is_empty());
        assert!(result.api_calls.is_empty());
        assert!(result.final_value.is_none());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_sandbox_result_with_error() {
        let result = SandboxResult::with_error("test error");
        assert_eq!(result.error, Some("test error".to_string()));
    }

    #[test]
    fn test_sandbox_result_serialization() {
        let result = SandboxResult {
            decoded_strings: vec![DecodedString {
                function: "atob".to_string(),
                input: "aGVsbG8=".to_string(),
                output: "hello".to_string(),
            }],
            api_calls: vec![ApiCall {
                function: "fetch".to_string(),
                arguments: vec![serde_json::json!("https://example.com")],
            }],
            final_value: Some("result".to_string()),
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: SandboxResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decoded_strings.len(), 1);
        assert_eq!(parsed.api_calls.len(), 1);
    }
}
