# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Extension Analyzer is a Rust CLI tool for analyzing Chrome and Firefox browser extensions for security issues. It combines static analysis (AST-based JavaScript parsing via oxc, manifest permission analysis) with LLM-powered code review using multiple AI providers (OpenAI, Anthropic, Google Gemini).

## Build & Test Commands

```bash
cargo build                    # Debug build
cargo build --release          # Release binary
cargo check                    # Type check without building
cargo clippy                   # Lint checks (run before committing)
cargo test                     # Run all tests
cargo test --test javascript_tests  # Run specific test file
cargo test test_detect_eval_usage -- --exact  # Run single test
```

## Running the Tool

```bash
# Chrome extension by ID
cargo run -- nkbihfbeogaeaoehlefnkodbefgpgknn

# Firefox extension by slug
cargo run -- --firefox ublock-origin

# By URL (auto-detected)
cargo run -- "https://chromewebstore.google.com/detail/xxx"

# Local file
cargo run -- ./extension.crx

# With specific LLM provider
cargo run -- --llm anthropic <id>

# Static analysis only (no LLM)
cargo run -- --no-llm <id>
```

Environment variables for LLM providers: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`

## Architecture

### Data Flow Pipeline

```
Input Detection → Download → Extract → Static Analysis → LLM Analysis → Output
```

### Module Structure

- `src/main.rs` - CLI entry point, orchestrates the pipeline
- `src/input/` - Classifies input as Chrome ID, Firefox slug, URL, or local file
- `src/download/` - Chrome Web Store and Firefox Add-ons download clients (trait-based)
- `src/unpack/` - CRX3 and XPI/ZIP archive extraction
- `src/analyze/` - Static analysis orchestration
  - `manifest.rs` - Permission analysis with severity classification
  - `javascript.rs` - Oxc-based AST analysis with regex fallback (~31KB, the most complex module)
  - `patterns.rs` - Suspicious pattern definitions
- `src/llm/` - LLM integration via rig-core
  - `provider.rs` - Provider enum and client creation
  - `agents.rs` - Parallel task execution (ManifestReview, ScriptAnalysis, EndpointAnalysis, FinalSummary)
- `src/output/terminal.rs` - Colored CLI output with markdown rendering via termimad
- `src/models/` - Data types: Extension, Finding, Endpoint, Manifest

### Sandbox Module (`src/sandbox/`)

The sandbox module provides isolated JavaScript execution for deobfuscation:

- `execute_snippet(code, timeout_ms)` - Run JS in QuickJS sandbox
- Returns `SandboxResult` with decoded strings, API call traces, final value
- Used by LLM agents to decode `String.fromCharCode`, `atob`, etc.
- Completely isolated: no network, no filesystem, memory limited

### Key Patterns

- **Trait abstraction**: `Downloader` trait for pluggable download implementations
- **Visitor pattern**: `JsAnalyzer` implements oxc's `Visit` trait for AST traversal
- **Lazy regex**: `once_cell::Lazy` for compile-once patterns
- **Builder pattern**: `Finding::new().with_description().with_location().with_snippet()`
- **Async parallelism**: `futures::join_all()` for concurrent LLM tasks

### Error Handling

Uses `anyhow::Result<T>` for flexible error propagation with `.context()` for diagnostics.

## Testing

Integration tests in `/tests/`:
- `input_tests.rs` - Input type detection
- `download_tests.rs` - Download URL construction
- `unpack_tests.rs` - Archive format detection
- `manifest_tests.rs` - Permission analysis
- `javascript_tests.rs` - AST-based code analysis

## Commit Convention

Format: `<type>: <description>` (e.g., `feat: add X`, `fix: resolve Y`)
