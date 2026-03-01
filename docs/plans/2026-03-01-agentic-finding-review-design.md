# Agentic Finding Review

## Problem

Static analysis flags code patterns like `String.fromCharCode()` as suspicious and presents them to the LLM as established facts ("STATIC ANALYSIS DETECTED OBFUSCATION"). The LLM rubber-stamps them rather than investigating whether they're actually malicious. A simple `String.fromCharCode(0xff)` for legitimate character conversion gets the same treatment as actual obfuscation.

## Solution

Replace the single-shot "here are the findings, confirm them" LLM call with a per-finding agentic review loop. Each static finding is passed individually to an LLM agent equipped with tools to investigate the extension's code. The agent can read files, search the codebase, and run code in the sandbox before delivering a verdict: confirm, downgrade, or dismiss.

## Architecture

### Data Flow

```
Static Analysis → Agentic Finding Review → Existing LLM Tasks → Output
                  (per-finding, with tools)  (manifest, endpoint, summary, dark patterns)
```

Each static finding gets reviewed individually. Reviewed findings replace the originals before being passed to the rest of the pipeline.

### Tools

Four tools implemented as rig `Tool` trait impls:

**read_file** — Read a file from the extracted extension by path.
- Args: `{ path: String }`
- Returns file contents, truncated at ~50KB
- Agent sees the file list in its system prompt

**search_code** — Search across all extension files for a pattern.
- Args: `{ pattern: String }`
- Substring/regex search, returns matching lines with file:line references
- Capped at 50 results

**run_sandbox** — Execute JavaScript in QuickJS sandbox.
- Args: `{ code: String }`
- Returns decoded strings, API call traces, final value
- Uses existing `execute_snippet()`, 2s timeout

**submit_verdict** — Terminal tool that ends the review loop.
- Args: `{ action: "confirm" | "downgrade" | "dismiss", new_severity?: String, reasoning: String }`
- When called, the loop ends for this finding

All tools hold an `Arc` reference to the extension's files and extract path. Read-only, no network, no writes.

### Agent Prompt

System prompt establishes the agent as an investigator, not a confirmer:

```
You are a security analyst reviewing a finding from static analysis of a browser
extension. Your job is to INVESTIGATE whether this finding represents a real security
concern or a false positive.

Static analysis flagged this code but may be wrong. Common false positives include:
- String.fromCharCode() used for legitimate character conversion
- atob() used for non-sensitive data decoding
- eval() in a build tool or test harness
- fetch() calls to the extension's own API

Use your tools to trace where values come from, read surrounding code, and understand
the actual intent. When you have enough evidence, call submit_verdict.

Extension files: [list of file paths]
```

Per-finding prompt includes title, severity, category, description, location, and code snippet.

### Loop Mechanics

- Uses rig's `.tool()` builder with `.multi_turn(MAX_TOOL_CALLS)`
- `MAX_TOOL_CALLS = 50` (configurable constant)
- When agent calls `submit_verdict`, loop ends naturally
- If budget exhausted without verdict, finding is kept as-is (fail-safe)
- Findings reviewed sequentially to control token costs and rate limits

### Verdict Handling

- **confirm** — finding stays with original severity
- **downgrade** — severity changed to `new_severity`, reasoning appended to description
- **dismiss** — finding removed from results, logged at debug level

## Integration

### Where It Plugs In

In `main.rs`, between static analysis and existing LLM tasks:

```rust
let mut result = analyze::analyze_extension(&extension).await?;

if !args.no_llm {
    result.findings = review_findings(&client, &extension, result.findings, model).await?;
}

// Existing LLM analysis continues with reviewed findings
```

### Changes to Existing Code

- `build_script_prompt` in `agents.rs`: remove "STATIC ANALYSIS DETECTED OBFUSCATION" section (the review agent now handles this judgment)
- ScriptAnalysis task stays — it discovers new issues the review agent doesn't cover

### CLI

No new flags. `--no-llm` skips both review and existing LLM tasks. Same `--llm` provider and `--model`.

### Output

Reviewed findings that were downgraded show the reasoning:

```
[INFO] String.fromCharCode() usage
  Agent review: Downgraded from MEDIUM. This is legitimate UTF-8 byte conversion
  for the extension's i18n module. The values are hardcoded constants, not dynamic
  user input.
```

## File Changes

### New Files

- `src/llm/review_agent.rs` — review loop orchestration, verdict types
- `src/llm/tools.rs` — Tool trait implementations

### Modified Files

- `src/llm/mod.rs` — export new modules
- `src/llm/agents.rs` — remove obfuscation prompt section from `build_script_prompt`
- `src/main.rs` — insert review step between static analysis and LLM tasks
- `src/models/finding.rs` — add `review_reasoning: Option<String>` to `Finding`
- `src/output/terminal.rs` — display review reasoning when present

### Dependencies

- `schemars` — required for rig's `Tool` trait (`JsonSchema` derive on tool args)
- No other new dependencies
