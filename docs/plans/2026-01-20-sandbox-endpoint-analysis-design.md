# Sandbox-Enhanced Endpoint Analysis - Design

## Overview

When static analysis detects a `fetch()` or `XMLHttpRequest` call but can only identify variable names (not actual data sources), we extract the surrounding code context and run it in the sandbox. The sandbox traces what arguments are actually passed to network APIs.

**Problem:** Static analysis shows `Sends: assetType, assetId` but can't reveal the actual data values or where they came from.

**Solution:** Pre-run suspicious code in the sandbox and include traced results in the LLM prompt.

## Data Flow

```
JavaScript files
     ↓
Static Analysis (javascript.rs)
     ↓
Endpoints with Unknown data sources
     ↓
Sandbox Analysis Pass (new)
     ↓
Enhanced Endpoints with traced arguments
     ↓
Terminal Output + LLM Prompt
```

## Code Extraction Strategy

### Finding the enclosing function

When we detect a fetch call at a specific location (file + line):

1. Parse the file with Oxc
2. Walk the AST to find the fetch call by span/location
3. Walk up the tree to find the enclosing `FunctionDeclaration`, `FunctionExpression`, `ArrowFunctionExpression`, or `MethodDefinition`
4. Extract that function's source text

### Tracing variable dependencies

The enclosing function may reference variables from outer scopes:

1. Collect all `Identifier` references in the function body
2. For each identifier, check if it's:
   - A function parameter → already available
   - Declared in the function → already available
   - Declared in outer scope → need to include that declaration
3. Recursively trace outer declarations

### Practical limits

- Max depth of 2 scope levels (function + immediate outer scope)
- Skip if enclosing function is >200 lines (too complex, likely noisy)
- Skip module-level fetch calls (no enclosing function to extract)

### Output example

```javascript
const API_BASE = "https://roearn-api.com";
function submitItem(assetType, assetId) {
  fetch(API_BASE + "/item_request", { body: JSON.stringify({assetType, assetId}) });
}
submitItem("gamepass", 12345);
```

## Sandbox Execution & Result Handling

### Invoking the function

Extracting the function isn't enough - we need to call it:

1. If function has parameters, infer reasonable test values:
   - String params: `"test"`
   - Number params: `12345`
   - Object params: `{}`
   - Unknown: `null`
2. Append a call to the function at the end of the snippet
3. For anonymous functions assigned to variables, call the variable

### Execution

```rust
let result = execute_snippet(&snippet, 2000); // 2 second timeout
```

### New data structure

```rust
pub struct SandboxTrace {
    pub fetch_calls: Vec<TracedFetch>,  // URL + method + body
    pub decoded_strings: Vec<String>,    // Revealed obfuscated content
    pub partial: bool,                   // True if error/timeout occurred
    pub error: Option<String>,           // What went wrong, if anything
}
```

### Matching traces to endpoints

After sandbox runs, match traced fetch URLs to detected endpoints. If `sandbox_trace.fetch_calls` contains a URL matching an endpoint, attach the trace to that endpoint.

## Output Integration

### Terminal output

When an endpoint has a sandbox trace:

```
https://roearn-api.com/item_request
  → POST   (background.js:301)
      Sends: assetType, assetId
      Traced: body = {"assetType":"gamepass","assetId":98765}
```

If partial results:

```
      Traced (partial): decoded "aHR0cHM6Ly9..." → "https://evil.com"
      Sandbox: ReferenceError - userId not defined
```

### LLM prompt

Enhance the endpoint analysis prompt:

```
Endpoint: POST https://roearn-api.com/item_request (background.js:301)
  Static analysis: sends variables assetType, assetId
  Sandbox execution: fetch called with body = {"assetType":"gamepass","assetId":98765}
```

## File Structure

### New files

- `src/analyze/sandbox_analysis.rs` - Main logic for code extraction and sandbox execution

### Modified files

- `src/analyze/mod.rs` - Export new module
- `src/models/endpoint.rs` - Add `SandboxTrace` struct and field on `Endpoint`
- `src/output/terminal.rs` - Display sandbox traces
- `src/llm/agents.rs` - Include traces in endpoint prompt
- `src/main.rs` - Call sandbox analysis pass after static analysis

### Public API

```rust
// src/analyze/sandbox_analysis.rs
pub fn analyze_endpoints_with_sandbox(
    endpoints: &mut [Endpoint],
    files: &[ExtensionFile],
) -> Vec<Finding>;
```

## Testing

- Unit tests for code extraction (find enclosing function, trace dependencies)
- Integration test with a sample extension file containing fetch calls
- Test partial results when sandbox times out

## Performance Constraints

- Only analyze endpoints with `Unknown` data sources
- Skip files >50KB (likely bundled/minified, sandbox won't help)
- 2 second timeout per snippet
- Max 20 endpoints to sandbox per analysis (configurable)
