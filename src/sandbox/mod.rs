mod trace;

pub use trace::{ApiCall, DecodedString, SandboxResult};

/// Execute a JavaScript snippet in the sandbox
///
/// Returns decoded strings, traced API calls, and the final expression value.
/// Execution is isolated - no network or filesystem access is possible.
pub fn execute_snippet(code: &str, timeout_ms: u64) -> SandboxResult {
    // TODO: Implement in next task
    let _ = (code, timeout_ms);
    SandboxResult::with_error("Not yet implemented")
}
