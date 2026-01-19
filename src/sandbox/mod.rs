mod mocks;
mod runtime;
mod trace;

pub use trace::{ApiCall, DecodedString, SandboxResult};

/// Execute a JavaScript snippet in the sandbox
///
/// Returns decoded strings, traced API calls, and the final expression value.
/// Execution is isolated - no network or filesystem access is possible.
///
/// # Arguments
/// * `code` - JavaScript code to execute
/// * `timeout_ms` - Maximum execution time in milliseconds
///
/// # Example
/// ```
/// use extanalyzer::sandbox::execute_snippet;
///
/// let result = execute_snippet("atob('aGVsbG8=')", 1000);
/// assert_eq!(result.decoded_strings[0].output, "hello");
/// ```
pub fn execute_snippet(code: &str, timeout_ms: u64) -> SandboxResult {
    runtime::run_in_sandbox(code, timeout_ms)
}
