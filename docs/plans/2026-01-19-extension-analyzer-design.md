# Browser Extension Analyzer - Design Document

**Date:** 2026-01-19
**Status:** Approved

## Overview

A Rust CLI tool for downloading and analyzing Chrome/Firefox browser extensions using static code analysis and LLM-powered review. Designed for security research at scale and educational purposes.

## Goals

- Download extensions from Chrome Web Store and Firefox Add-ons
- Extract and parse extension contents (CRX3, XPI formats)
- Perform static analysis on JavaScript code using Oxc
- Detect dangerous permissions, suspicious API usage, and obfuscation
- Extract network endpoints and analyze data exfiltration patterns
- Use LLM subagents for focused, parallel code analysis
- Produce detailed, educational CLI output

## Non-Goals (For Now)

- Dynamic/sandboxed analysis (designed for future addition)
- Web UI or HTML reports
- Browser integration

---

## CLI Interface

```bash
# Single extension by Chrome ID
extanalyzer nkbihfbeogaeaoehlefnkodbefgpgknn

# Single extension by Firefox slug
extanalyzer --firefox ublock-origin

# By URL (auto-detects store)
extanalyzer "https://chromewebstore.google.com/detail/xxx"

# Local file
extanalyzer ./suspicious.crx

# Batch mode
extanalyzer --batch extensions.txt

# LLM provider selection
extanalyzer --llm openai <id>      # default
extanalyzer --llm anthropic <id>
extanalyzer --llm gemini <id>
extanalyzer --llm ollama <id>      # local
extanalyzer --no-llm <id>          # static analysis only
```

**Input Detection Logic:**
- 32 alphanumeric chars → Chrome extension ID
- Contains `chromewebstore.google.com` → Chrome URL
- Contains `addons.mozilla.org` → Firefox URL
- Ends with `.crx` or `.xpi` → local file
- `--batch` flag → read lines from file

---

## Architecture

```
Input → Download → Unpack → Analyze → Report
              ↓
         [cache dir]
```

### Module Structure

```
src/
├── main.rs              # CLI entry point, argument parsing
├── lib.rs               # Public API for library use
├── input/
│   └── mod.rs           # Input detection & normalization
├── download/
│   ├── mod.rs           # Trait + common logic
│   ├── chrome.rs        # Chrome Web Store client
│   └── firefox.rs       # Firefox Add-ons client
├── unpack/
│   ├── mod.rs           # Extraction orchestration
│   ├── crx.rs           # CRX3 header parsing + ZIP extraction
│   └── xpi.rs           # XPI (plain ZIP) extraction
├── analyze/
│   ├── mod.rs           # Analysis orchestrator
│   ├── manifest.rs      # manifest.json parsing & permission analysis
│   ├── javascript.rs    # Oxc-based static analysis
│   └── patterns.rs      # Suspicious pattern definitions
├── llm/
│   ├── mod.rs           # LLM trait + provider selection
│   ├── openai.rs        # OpenAI client
│   ├── anthropic.rs     # Anthropic client
│   ├── gemini.rs        # Gemini client
│   └── ollama.rs        # Ollama client
└── output/
    ├── mod.rs           # Output formatting
    └── terminal.rs      # Colored CLI output
```

---

## Data Model

### Core Types

```rust
// Extension source
pub enum ExtensionSource {
    Chrome,
    Firefox,
    LocalFile,
}

// What we know about an extension
pub struct Extension {
    pub id: String,
    pub source: ExtensionSource,
    pub manifest: Manifest,
    pub files: Vec<ExtensionFile>,
}

// A single finding from analysis
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub description: String,        // Educational explanation
    pub location: Option<Location>,
    pub code_snippet: Option<String>,
}

pub enum Severity {
    Critical,  // Likely malicious or extremely dangerous
    High,      // Significant security/privacy risk
    Medium,    // Moderate concern, worth investigating
    Low,       // Minor issue or unusual pattern
    Info,      // Educational note, not necessarily bad
}

pub enum Category {
    Permission,     // Risky manifest permissions
    ApiUsage,       // Dangerous browser API calls
    Network,        // External URLs, data exfiltration patterns
    Obfuscation,    // Encoded strings, eval, dynamic code
    Cryptography,   // Crypto mining, wallet addresses
    DataAccess,     // Cookies, storage, form data access
}
```

### Network Endpoints

```rust
pub struct Endpoint {
    pub url: String,
    pub method: Option<HttpMethod>,
    pub payload_fields: Vec<String>,  // e.g., ["email", "cookies"]
    pub location: Location,
    pub context: EndpointContext,
}

pub enum EndpointContext {
    Analytics,        // Known analytics domains
    Telemetry,        // Extension's own telemetry
    Api,              // Legitimate API call
    Suspicious,       // Unknown domain + sensitive data
    KnownMalicious,   // Matches known bad domains
    Unknown,
}

pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Other(String),
}
```

### Analysis Result

```rust
pub struct AnalysisResult {
    pub extension: Extension,
    pub findings: Vec<Finding>,
    pub endpoints: Vec<Endpoint>,
    pub llm_summary: Option<String>,
}
```

---

## Static Analysis

Using Oxc for JavaScript parsing and AST traversal.

### API Usage Detection

```rust
const CRITICAL_APIS: &[&str] = &[
    "chrome.webRequest.onBeforeRequest",
    "chrome.cookies.getAll",
    "chrome.tabs.executeScript",
    "eval",
    "Function",
];

const HIGH_RISK_APIS: &[&str] = &[
    "chrome.history.search",
    "chrome.downloads.download",
    "chrome.storage.sync.get",
];
```

### Endpoint Extraction

1. Find string literals matching URL patterns (`https?://...`)
2. Track `fetch()` and `XMLHttpRequest.open()` calls
3. Follow variable assignments to resolve URLs where possible
4. Detect payload construction (object literals in fetch body)
5. Identify what data flows into payloads (cookies, history, form data)

### Obfuscation Detection

- `atob()` / `btoa()` with long strings
- `String.fromCharCode()` sequences
- Hex-encoded strings (`\x41\x42...`)
- Heavily minified code (heuristic)

---

## LLM Analysis

Using `rig-core` for LLM orchestration with subagent architecture.

### Subagent Types

```rust
pub enum AnalysisTask {
    ManifestReview(Manifest),           // Analyze permissions + metadata
    ScriptAnalysis(String, Location),   // Analyze a single JS file
    EndpointAnalysis(Vec<Endpoint>),    // Review extracted endpoints
    ObfuscationAnalysis(String),        // Decode/explain obfuscated code
    FinalSummary(Vec<Finding>),         // Synthesize all findings
}
```

### Chunking Strategy

- Each JS file analyzed separately (if under token limit)
- Large files split by function/block
- Manifest gets its own focused review
- Endpoints analyzed as a batch with context
- Final summary agent synthesizes everything

### Parallel Execution

```rust
pub async fn analyze_with_llm(extension: &Extension) -> Vec<Finding> {
    let tasks: Vec<AnalysisTask> = build_tasks(extension);

    // Run file analyses in parallel
    let results: Vec<Finding> = futures::future::join_all(
        tasks.iter().map(|t| self.run_task(t))
    ).await.into_iter().flatten().collect();

    // Final synthesis pass
    self.run_task(&AnalysisTask::FinalSummary(results)).await
}
```

### Supported Providers

- OpenAI (default)
- Anthropic
- Google Gemini
- Ollama (local)

---

## CLI Output Format

```
┌─────────────────────────────────────────────────────────────┐
│  Extension: uBlock Origin                                   │
│  ID: cjpalhdlnbpafiamejdnhcphjbkeiagm                       │
│  Version: 1.56.0 │ Manifest V3 │ Chrome                     │
└─────────────────────────────────────────────────────────────┘

── Permissions ──────────────────────────────────────────────
  ⚠ HIGH    <all_urls>
            Can access and modify content on all websites.

  ● LOW     storage
            Local data storage. Generally safe.

── Code Findings ────────────────────────────────────────────
  ✖ CRITICAL  Obfuscated code detected          background.js:142
              Long Base64 string decoded at runtime.

              │ 142:  const cfg = JSON.parse(atob("eyJhcGkiOi...
              │ 143:  fetch(cfg.endpoint, { body: cfg.payload })

              This pattern is commonly used to hide malicious
              URLs or configuration from static analysis.

── Network Endpoints ────────────────────────────────────────
  → POST https://api.example.com/telemetry
    Payload: { browserId, visitedUrls, timestamp }
    Context: SUSPICIOUS - sends browsing history to unknown server

  → GET https://filters.adblockcdn.com/rules.json
    Context: API - fetching filter rules (expected behavior)

── LLM Summary ──────────────────────────────────────────────
  This extension requests broad permissions but the code analysis
  reveals concerning data collection patterns...
```

Colors: Red (critical/high), Yellow (medium), Blue (info), Green (safe)

---

## Dependencies

```toml
[package]
name = "extanalyzer"
version = "0.1.0"
edition = "2021"

[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }
futures = "0.3"

# HTTP & downloading
reqwest = { version = "0.12", features = ["json", "stream"] }

# Archive handling
zip = "2.0"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# JavaScript parsing
oxc_parser = "0.56"
oxc_ast = "0.56"
oxc_allocator = "0.56"
oxc_span = "0.56"

# LLM integration
rig-core = { version = "0.6", features = ["all"] }

# Pattern matching
regex = "1"

# CLI
clap = { version = "4", features = ["derive"] }
colored = "2"

# Error handling
thiserror = "2"
anyhow = "1"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"
```

---

## Configuration

Environment variables:

```bash
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-...
GEMINI_API_KEY=...
OLLAMA_HOST=http://localhost:11434
EXTANALYZER_CACHE_DIR=~/.cache/extanalyzer
```

---

## Future Enhancements

- Sandboxed execution for dynamic analysis
- JSON output format for pipeline integration
- HTML reports for sharing
- Known malicious extension database
- Browser extension for real-time analysis
