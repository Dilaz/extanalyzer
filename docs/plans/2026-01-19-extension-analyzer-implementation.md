# Extension Analyzer Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust CLI tool that downloads and analyzes Chrome/Firefox extensions using static analysis and LLM review.

**Architecture:** Pipeline architecture (Input → Download → Unpack → Analyze → Report) with modular components. Static analysis uses Oxc for JS parsing. LLM analysis uses rig-core with subagents for parallel, focused code review.

**Tech Stack:** Rust, tokio, reqwest, zip, oxc, rig-core, clap, colored

---

## Task 1: Project Setup

**Files:**
- Modify: `Cargo.toml`
- Create: `src/lib.rs`
- Modify: `src/main.rs`

**Step 1: Update Cargo.toml with dependencies**

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
rig-core = "0.6"

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

[dev-dependencies]
tempfile = "3"
wiremock = "0.6"
tokio-test = "0.4"
```

**Step 2: Create src/lib.rs**

```rust
pub mod input;
pub mod download;
pub mod unpack;
pub mod analyze;
pub mod llm;
pub mod output;
pub mod models;

pub use models::*;
```

**Step 3: Update src/main.rs with basic structure**

```rust
use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "extanalyzer")]
#[command(about = "Analyze Chrome and Firefox browser extensions")]
struct Args {
    /// Extension ID, URL, or file path
    #[arg(required_unless_present = "batch")]
    input: Option<String>,

    /// Analyze Firefox extension (default is Chrome)
    #[arg(long)]
    firefox: bool,

    /// Batch file with extension IDs/URLs
    #[arg(long)]
    batch: Option<String>,

    /// LLM provider (openai, anthropic, gemini, ollama)
    #[arg(long, default_value = "openai")]
    llm: String,

    /// Skip LLM analysis
    #[arg(long)]
    no_llm: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    println!("extanalyzer v{}", env!("CARGO_PKG_VERSION"));
    println!("Args: {:?}", args);
    Ok(())
}
```

**Step 4: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully (warnings OK for now)

**Step 5: Verify CLI help works**

Run: `cargo run -- --help`
Expected: Shows help with all options

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: project setup with dependencies and CLI skeleton"
```

---

## Task 2: Core Data Models

**Files:**
- Create: `src/models/mod.rs`
- Create: `src/models/extension.rs`
- Create: `src/models/finding.rs`
- Create: `src/models/endpoint.rs`

**Step 1: Create models module**

Create `src/models/mod.rs`:

```rust
mod extension;
mod finding;
mod endpoint;

pub use extension::*;
pub use finding::*;
pub use endpoint::*;
```

**Step 2: Create extension model**

Create `src/models/extension.rs`:

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionSource {
    Chrome,
    Firefox,
    LocalFile,
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub source: ExtensionSource,
    pub manifest: Option<Manifest>,
    pub files: Vec<ExtensionFile>,
    pub extract_path: Option<PathBuf>,
}

impl Extension {
    pub fn new(id: String, source: ExtensionSource) -> Self {
        Self {
            id,
            name: None,
            version: None,
            source,
            manifest: None,
            files: Vec::new(),
            extract_path: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtensionFile {
    pub path: PathBuf,
    pub content: Option<String>,
    pub file_type: FileType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileType {
    JavaScript,
    Json,
    Html,
    Css,
    Image,
    Other,
}

impl FileType {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "js" | "mjs" | "cjs" => FileType::JavaScript,
            "json" => FileType::Json,
            "html" | "htm" => FileType::Html,
            "css" => FileType::Css,
            "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" => FileType::Image,
            _ => FileType::Other,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub name: Option<String>,
    pub version: Option<String>,
    pub manifest_version: Option<u8>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub host_permissions: Option<Vec<String>>,
    pub content_scripts: Option<Vec<ContentScript>>,
    pub background: Option<Background>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContentScript {
    pub matches: Option<Vec<String>>,
    pub js: Option<Vec<String>>,
    pub css: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Background {
    pub service_worker: Option<String>,
    pub scripts: Option<Vec<String>>,
}
```

**Step 3: Create finding model**

Create `src/models/finding.rs`:

```rust
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Category {
    Permission,
    ApiUsage,
    Network,
    Obfuscation,
    Cryptography,
    DataAccess,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Permission => "Permission",
            Category::ApiUsage => "API Usage",
            Category::Network => "Network",
            Category::Obfuscation => "Obfuscation",
            Category::Cryptography => "Cryptography",
            Category::DataAccess => "Data Access",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub file: PathBuf,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.file.display())?;
        if let Some(line) = self.line {
            write!(f, ":{}", line)?;
            if let Some(col) = self.column {
                write!(f, ":{}", col)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub description: String,
    pub location: Option<Location>,
    pub code_snippet: Option<String>,
}

impl Finding {
    pub fn new(severity: Severity, category: Category, title: impl Into<String>) -> Self {
        Self {
            severity,
            category,
            title: title.into(),
            description: String::new(),
            location: None,
            code_snippet: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.code_snippet = Some(snippet.into());
        self
    }
}
```

**Step 4: Create endpoint model**

Create `src/models/endpoint.rs`:

```rust
use super::Location;

#[derive(Debug, Clone, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Other(String),
}

impl HttpMethod {
    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Other(s) => s,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EndpointContext {
    Analytics,
    Telemetry,
    Api,
    Suspicious,
    KnownMalicious,
    Unknown,
}

impl EndpointContext {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointContext::Analytics => "ANALYTICS",
            EndpointContext::Telemetry => "TELEMETRY",
            EndpointContext::Api => "API",
            EndpointContext::Suspicious => "SUSPICIOUS",
            EndpointContext::KnownMalicious => "MALICIOUS",
            EndpointContext::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: String,
    pub method: Option<HttpMethod>,
    pub payload_fields: Vec<String>,
    pub location: Location,
    pub context: EndpointContext,
    pub description: Option<String>,
}

impl Endpoint {
    pub fn new(url: String, location: Location) -> Self {
        Self {
            url,
            method: None,
            payload_fields: Vec::new(),
            location,
            context: EndpointContext::Unknown,
            description: None,
        }
    }

    pub fn with_method(mut self, method: HttpMethod) -> Self {
        self.method = Some(method);
        self
    }

    pub fn with_payload(mut self, fields: Vec<String>) -> Self {
        self.payload_fields = fields;
        self
    }

    pub fn with_context(mut self, context: EndpointContext) -> Self {
        self.context = context;
        self
    }
}
```

**Step 5: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add core data models (Extension, Finding, Endpoint)"
```

---

## Task 3: Input Detection Module

**Files:**
- Create: `src/input/mod.rs`
- Create: `tests/input_tests.rs`

**Step 1: Write tests for input detection**

Create `tests/input_tests.rs`:

```rust
use extanalyzer::input::{InputType, detect_input};

#[test]
fn test_detect_chrome_extension_id() {
    let input = "nkbihfbeogaeaoehlefnkodbefgpgknn";
    assert_eq!(detect_input(input), InputType::ChromeId(input.to_string()));
}

#[test]
fn test_detect_chrome_url() {
    let input = "https://chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn";
    assert!(matches!(detect_input(input), InputType::ChromeUrl(_)));
}

#[test]
fn test_detect_firefox_url() {
    let input = "https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/";
    assert!(matches!(detect_input(input), InputType::FirefoxUrl(_)));
}

#[test]
fn test_detect_local_crx() {
    let input = "./extension.crx";
    assert!(matches!(detect_input(input), InputType::LocalFile(_)));
}

#[test]
fn test_detect_local_xpi() {
    let input = "/home/user/addon.xpi";
    assert!(matches!(detect_input(input), InputType::LocalFile(_)));
}

#[test]
fn test_detect_firefox_slug() {
    // Short strings that aren't 32 chars and not a path
    let input = "ublock-origin";
    assert_eq!(detect_input(input), InputType::FirefoxSlug(input.to_string()));
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test input_tests`
Expected: FAIL - module not found

**Step 3: Create input detection module**

Create `src/input/mod.rs`:

```rust
use std::path::Path;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub enum InputType {
    ChromeId(String),
    ChromeUrl(String),
    FirefoxUrl(String),
    FirefoxSlug(String),
    LocalFile(String),
    BatchFile(String),
}

pub fn detect_input(input: &str) -> InputType {
    let input = input.trim();

    // Check for local file first (ends with .crx or .xpi, or is a path)
    if input.ends_with(".crx") || input.ends_with(".xpi") {
        return InputType::LocalFile(input.to_string());
    }

    // Check for Chrome Web Store URL
    if input.contains("chromewebstore.google.com") || input.contains("chrome.google.com/webstore") {
        return InputType::ChromeUrl(input.to_string());
    }

    // Check for Firefox Add-ons URL
    if input.contains("addons.mozilla.org") {
        return InputType::FirefoxUrl(input.to_string());
    }

    // Check for Chrome extension ID (32 alphanumeric lowercase chars)
    let chrome_id_re = Regex::new(r"^[a-z]{32}$").unwrap();
    if chrome_id_re.is_match(input) {
        return InputType::ChromeId(input.to_string());
    }

    // Check if it's a file path that exists
    if Path::new(input).exists() {
        return InputType::LocalFile(input.to_string());
    }

    // Default: assume Firefox slug (addon name)
    InputType::FirefoxSlug(input.to_string())
}

pub fn extract_chrome_id_from_url(url: &str) -> Option<String> {
    let chrome_id_re = Regex::new(r"[a-z]{32}").unwrap();
    chrome_id_re.find(url).map(|m| m.as_str().to_string())
}

pub fn extract_firefox_slug_from_url(url: &str) -> Option<String> {
    // Pattern: /addon/{slug}/ or /addon/{slug}
    let slug_re = Regex::new(r"/addon/([^/?]+)").unwrap();
    slug_re.captures(url).map(|c| c[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_chrome_id() {
        let url = "https://chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn";
        assert_eq!(
            extract_chrome_id_from_url(url),
            Some("nkbihfbeogaeaoehlefnkodbefgpgknn".to_string())
        );
    }

    #[test]
    fn test_extract_firefox_slug() {
        let url = "https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/";
        assert_eq!(
            extract_firefox_slug_from_url(url),
            Some("ublock-origin".to_string())
        );
    }
}
```

**Step 4: Update lib.rs to export input module**

```rust
pub mod input;
pub mod models;

pub use models::*;
```

**Step 5: Run tests to verify they pass**

Run: `cargo test --test input_tests`
Expected: All 6 tests pass

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add input detection module for extension IDs, URLs, and files"
```

---

## Task 4: Chrome Download Module

**Files:**
- Create: `src/download/mod.rs`
- Create: `src/download/chrome.rs`
- Create: `tests/download_tests.rs`

**Step 1: Write test for Chrome download URL generation**

Create `tests/download_tests.rs`:

```rust
use extanalyzer::download::chrome::ChromeDownloader;

#[test]
fn test_chrome_download_url_generation() {
    let downloader = ChromeDownloader::new();
    let url = downloader.build_download_url("nkbihfbeogaeaoehlefnkodbefgpgknn");

    assert!(url.contains("clients2.google.com"));
    assert!(url.contains("nkbihfbeogaeaoehlefnkodbefgpgknn"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test download_tests`
Expected: FAIL - module not found

**Step 3: Create download module**

Create `src/download/mod.rs`:

```rust
pub mod chrome;
pub mod firefox;

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Downloader {
    async fn download(&self, id: &str) -> Result<Vec<u8>>;
}
```

Note: Add `async-trait = "0.1"` to Cargo.toml dependencies.

**Step 4: Create Chrome downloader**

Create `src/download/chrome.rs`:

```rust
use anyhow::{Context, Result};
use async_trait::async_trait;
use super::Downloader;

pub struct ChromeDownloader {
    client: reqwest::Client,
}

impl ChromeDownloader {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    pub fn build_download_url(&self, extension_id: &str) -> String {
        format!(
            "https://clients2.google.com/service/update2/crx?\
             response=redirect&prodversion=130.0.0.0&\
             acceptformat=crx2,crx3&x=id%3D{}%26uc",
            extension_id
        )
    }
}

impl Default for ChromeDownloader {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Downloader for ChromeDownloader {
    async fn download(&self, extension_id: &str) -> Result<Vec<u8>> {
        let url = self.build_download_url(extension_id);

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to send download request")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Download failed with status {}: {}",
                response.status(),
                extension_id
            );
        }

        let bytes = response
            .bytes()
            .await
            .context("Failed to read response bytes")?;

        Ok(bytes.to_vec())
    }
}
```

**Step 5: Create Firefox downloader stub**

Create `src/download/firefox.rs`:

```rust
use anyhow::{Context, Result};
use async_trait::async_trait;
use super::Downloader;

pub struct FirefoxDownloader {
    client: reqwest::Client,
}

impl FirefoxDownloader {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0")
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    pub fn build_download_url(&self, slug: &str) -> String {
        format!(
            "https://addons.mozilla.org/firefox/downloads/latest/{}/latest.xpi",
            slug
        )
    }
}

impl Default for FirefoxDownloader {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Downloader for FirefoxDownloader {
    async fn download(&self, slug: &str) -> Result<Vec<u8>> {
        let url = self.build_download_url(slug);

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to send download request")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Download failed with status {}: {}",
                response.status(),
                slug
            );
        }

        let bytes = response
            .bytes()
            .await
            .context("Failed to read response bytes")?;

        Ok(bytes.to_vec())
    }
}
```

**Step 6: Update lib.rs**

```rust
pub mod input;
pub mod download;
pub mod models;

pub use models::*;
```

**Step 7: Add async-trait to Cargo.toml**

Add to `[dependencies]`:
```toml
async-trait = "0.1"
```

**Step 8: Run test to verify it passes**

Run: `cargo test --test download_tests`
Expected: PASS

**Step 9: Commit**

```bash
git add -A
git commit -m "feat: add Chrome and Firefox download modules"
```

---

## Task 5: Unpack Module (CRX and XPI)

**Files:**
- Create: `src/unpack/mod.rs`
- Create: `src/unpack/crx.rs`
- Create: `src/unpack/xpi.rs`
- Create: `tests/unpack_tests.rs`

**Step 1: Write tests for unpacking**

Create `tests/unpack_tests.rs`:

```rust
use extanalyzer::unpack::{detect_format, ExtensionFormat};

#[test]
fn test_detect_crx_format() {
    // CRX3 magic: "Cr24"
    let crx_data = b"Cr24\x03\x00\x00\x00";
    assert_eq!(detect_format(crx_data), ExtensionFormat::Crx3);
}

#[test]
fn test_detect_zip_format() {
    // ZIP magic: "PK\x03\x04"
    let zip_data = b"PK\x03\x04";
    assert_eq!(detect_format(zip_data), ExtensionFormat::Zip);
}

#[test]
fn test_detect_unknown_format() {
    let unknown = b"UNKNOWN";
    assert_eq!(detect_format(unknown), ExtensionFormat::Unknown);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test unpack_tests`
Expected: FAIL - module not found

**Step 3: Create unpack module**

Create `src/unpack/mod.rs`:

```rust
pub mod crx;
pub mod xpi;

use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionFormat {
    Crx3,
    Zip,  // XPI files are plain ZIP
    Unknown,
}

pub fn detect_format(data: &[u8]) -> ExtensionFormat {
    if data.len() < 4 {
        return ExtensionFormat::Unknown;
    }

    // CRX3 magic: "Cr24" followed by version 3
    if data.starts_with(b"Cr24") {
        return ExtensionFormat::Crx3;
    }

    // ZIP magic: "PK\x03\x04"
    if data.starts_with(b"PK\x03\x04") {
        return ExtensionFormat::Zip;
    }

    ExtensionFormat::Unknown
}

pub fn extract(data: &[u8], output_dir: &Path) -> Result<()> {
    match detect_format(data) {
        ExtensionFormat::Crx3 => crx::extract_crx(data, output_dir),
        ExtensionFormat::Zip => xpi::extract_zip(data, output_dir),
        ExtensionFormat::Unknown => anyhow::bail!("Unknown extension format"),
    }
}
```

**Step 4: Create CRX extractor**

Create `src/unpack/crx.rs`:

```rust
use anyhow::{Context, Result};
use std::io::Cursor;
use std::path::Path;
use zip::ZipArchive;

pub fn extract_crx(data: &[u8], output_dir: &Path) -> Result<()> {
    // CRX3 format:
    // - Magic: "Cr24" (4 bytes)
    // - Version: 3 (4 bytes, little-endian)
    // - Header length (4 bytes, little-endian)
    // - Header (protobuf, variable length)
    // - ZIP data

    if data.len() < 12 {
        anyhow::bail!("CRX file too small");
    }

    if !data.starts_with(b"Cr24") {
        anyhow::bail!("Invalid CRX magic");
    }

    let version = u32::from_le_bytes(data[4..8].try_into()?);
    if version != 3 {
        anyhow::bail!("Unsupported CRX version: {}", version);
    }

    let header_len = u32::from_le_bytes(data[8..12].try_into()?) as usize;
    let zip_start = 12 + header_len;

    if zip_start >= data.len() {
        anyhow::bail!("Invalid CRX header length");
    }

    let zip_data = &data[zip_start..];

    let cursor = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(cursor)
        .context("Failed to read ZIP from CRX")?;

    archive.extract(output_dir)
        .context("Failed to extract CRX contents")?;

    Ok(())
}
```

**Step 5: Create XPI/ZIP extractor**

Create `src/unpack/xpi.rs`:

```rust
use anyhow::{Context, Result};
use std::io::Cursor;
use std::path::Path;
use zip::ZipArchive;

pub fn extract_zip(data: &[u8], output_dir: &Path) -> Result<()> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)
        .context("Failed to read ZIP archive")?;

    archive.extract(output_dir)
        .context("Failed to extract ZIP contents")?;

    Ok(())
}
```

**Step 6: Update lib.rs**

```rust
pub mod input;
pub mod download;
pub mod unpack;
pub mod models;

pub use models::*;
```

**Step 7: Run tests to verify they pass**

Run: `cargo test --test unpack_tests`
Expected: All 3 tests pass

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: add CRX and XPI unpack modules"
```

---

## Task 6: Manifest Parser

**Files:**
- Create: `src/analyze/mod.rs`
- Create: `src/analyze/manifest.rs`
- Create: `tests/manifest_tests.rs`

**Step 1: Write tests for manifest parsing**

Create `tests/manifest_tests.rs`:

```rust
use extanalyzer::analyze::manifest::{parse_manifest, analyze_permissions};
use extanalyzer::models::Severity;

#[test]
fn test_parse_manifest() {
    let json = r#"{
        "name": "Test Extension",
        "version": "1.0.0",
        "manifest_version": 3,
        "permissions": ["storage", "tabs"]
    }"#;

    let manifest = parse_manifest(json).unwrap();
    assert_eq!(manifest.name, Some("Test Extension".to_string()));
    assert_eq!(manifest.manifest_version, Some(3));
}

#[test]
fn test_analyze_dangerous_permissions() {
    let json = r#"{
        "name": "Dangerous Extension",
        "manifest_version": 3,
        "permissions": ["<all_urls>", "webRequestBlocking", "cookies"]
    }"#;

    let manifest = parse_manifest(json).unwrap();
    let findings = analyze_permissions(&manifest);

    // Should find critical issues
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));
}

#[test]
fn test_analyze_safe_permissions() {
    let json = r#"{
        "name": "Safe Extension",
        "manifest_version": 3,
        "permissions": ["storage"]
    }"#;

    let manifest = parse_manifest(json).unwrap();
    let findings = analyze_permissions(&manifest);

    // Should not find critical or high issues
    assert!(!findings.iter().any(|f| f.severity == Severity::Critical || f.severity == Severity::High));
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test manifest_tests`
Expected: FAIL - module not found

**Step 3: Create analyze module**

Create `src/analyze/mod.rs`:

```rust
pub mod manifest;
pub mod javascript;
pub mod patterns;

use crate::models::{Extension, Finding, Endpoint};
use anyhow::Result;

pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub endpoints: Vec<Endpoint>,
    pub llm_summary: Option<String>,
}

pub async fn analyze_extension(extension: &Extension) -> Result<AnalysisResult> {
    let mut findings = Vec::new();
    let mut endpoints = Vec::new();

    // Analyze manifest permissions
    if let Some(ref manifest) = extension.manifest {
        findings.extend(manifest::analyze_permissions(manifest));
    }

    // Analyze JavaScript files
    for file in &extension.files {
        if let crate::models::FileType::JavaScript = file.file_type {
            if let Some(ref content) = file.content {
                let (js_findings, js_endpoints) = javascript::analyze_javascript(content, &file.path);
                findings.extend(js_findings);
                endpoints.extend(js_endpoints);
            }
        }
    }

    Ok(AnalysisResult {
        findings,
        endpoints,
        llm_summary: None,
    })
}
```

**Step 4: Create manifest analyzer**

Create `src/analyze/manifest.rs`:

```rust
use crate::models::{Finding, Manifest, Severity, Category};
use anyhow::Result;

pub fn parse_manifest(json: &str) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_str(json)?;
    Ok(manifest)
}

pub fn analyze_permissions(manifest: &Manifest) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(ref permissions) = manifest.permissions {
        for perm in permissions {
            if let Some(finding) = analyze_single_permission(perm) {
                findings.push(finding);
            }
        }
    }

    if let Some(ref host_permissions) = manifest.host_permissions {
        for perm in host_permissions {
            if let Some(finding) = analyze_single_permission(perm) {
                findings.push(finding);
            }
        }
    }

    findings
}

fn analyze_single_permission(perm: &str) -> Option<Finding> {
    match perm {
        "<all_urls>" | "*://*/*" | "http://*/*" | "https://*/*" => {
            Some(Finding::new(Severity::Critical, Category::Permission, format!("Broad host access: {}", perm))
                .with_description("Can access and modify content on all websites. This is extremely powerful and commonly abused by malicious extensions."))
        }
        "webRequestBlocking" => {
            Some(Finding::new(Severity::Critical, Category::Permission, "webRequestBlocking permission")
                .with_description("Can intercept, block, and modify all network requests. Often used for data theft or ad injection."))
        }
        "cookies" => {
            Some(Finding::new(Severity::High, Category::Permission, "cookies permission")
                .with_description("Can read and modify cookies for all sites. Could be used to steal session tokens."))
        }
        "webRequest" => {
            Some(Finding::new(Severity::High, Category::Permission, "webRequest permission")
                .with_description("Can observe all network requests. Useful for monitoring but can leak browsing activity."))
        }
        "tabs" => {
            Some(Finding::new(Severity::Medium, Category::Permission, "tabs permission")
                .with_description("Can see URLs and titles of all open tabs. Could leak browsing activity."))
        }
        "history" => {
            Some(Finding::new(Severity::High, Category::Permission, "history permission")
                .with_description("Can read and modify browsing history. Significant privacy concern."))
        }
        "downloads" => {
            Some(Finding::new(Severity::Medium, Category::Permission, "downloads permission")
                .with_description("Can manage downloads. Could be used to download malicious files."))
        }
        "storage" => {
            Some(Finding::new(Severity::Low, Category::Permission, "storage permission")
                .with_description("Local storage access. Generally safe, used for storing extension settings."))
        }
        "activeTab" => {
            Some(Finding::new(Severity::Info, Category::Permission, "activeTab permission")
                .with_description("Temporary access to active tab when user invokes the extension. Safe, limited scope."))
        }
        _ if perm.starts_with("http") || perm.contains("*") => {
            Some(Finding::new(Severity::Medium, Category::Permission, format!("Host permission: {}", perm))
                .with_description(format!("Can access content on matching URLs: {}", perm)))
        }
        _ => None,
    }
}
```

**Step 5: Create stub for JavaScript analyzer**

Create `src/analyze/javascript.rs`:

```rust
use crate::models::{Finding, Endpoint};
use std::path::Path;

pub fn analyze_javascript(_content: &str, _path: &Path) -> (Vec<Finding>, Vec<Endpoint>) {
    // Stub - will implement with Oxc in next task
    (Vec::new(), Vec::new())
}
```

**Step 6: Create patterns stub**

Create `src/analyze/patterns.rs`:

```rust
// Suspicious pattern definitions - will be used by JavaScript analyzer

pub const CRITICAL_APIS: &[&str] = &[
    "chrome.webRequest.onBeforeRequest",
    "chrome.cookies.getAll",
    "chrome.cookies.get",
    "chrome.tabs.executeScript",
    "browser.webRequest.onBeforeRequest",
    "browser.cookies.getAll",
    "eval",
    "Function(",
];

pub const HIGH_RISK_APIS: &[&str] = &[
    "chrome.history.search",
    "chrome.downloads.download",
    "chrome.storage.sync.get",
    "chrome.tabs.query",
    "browser.history.search",
    "browser.downloads.download",
    "document.cookie",
    "localStorage",
    "sessionStorage",
];

pub const OBFUSCATION_PATTERNS: &[&str] = &[
    "atob(",
    "btoa(",
    "String.fromCharCode",
    "charCodeAt",
    "\\x",
    "\\u00",
];
```

**Step 7: Update lib.rs**

```rust
pub mod input;
pub mod download;
pub mod unpack;
pub mod analyze;
pub mod models;

pub use models::*;
```

**Step 8: Run tests to verify they pass**

Run: `cargo test --test manifest_tests`
Expected: All 3 tests pass

**Step 9: Commit**

```bash
git add -A
git commit -m "feat: add manifest parser and permission analyzer"
```

---

## Task 7: JavaScript Static Analysis with Oxc

**Files:**
- Modify: `src/analyze/javascript.rs`
- Create: `tests/javascript_tests.rs`

**Step 1: Write tests for JavaScript analysis**

Create `tests/javascript_tests.rs`:

```rust
use extanalyzer::analyze::javascript::analyze_javascript;
use extanalyzer::models::{Severity, Category};
use std::path::PathBuf;

#[test]
fn test_detect_eval_usage() {
    let code = r#"
        const code = "alert('hi')";
        eval(code);
    "#;

    let (findings, _) = analyze_javascript(code, &PathBuf::from("test.js"));

    assert!(findings.iter().any(|f|
        f.severity == Severity::Critical &&
        f.title.contains("eval")
    ));
}

#[test]
fn test_detect_fetch_endpoint() {
    let code = r#"
        fetch("https://api.example.com/data", {
            method: "POST",
            body: JSON.stringify({ userId: id })
        });
    "#;

    let (_, endpoints) = analyze_javascript(code, &PathBuf::from("test.js"));

    assert!(endpoints.iter().any(|e| e.url.contains("api.example.com")));
}

#[test]
fn test_detect_chrome_api() {
    let code = r#"
        chrome.cookies.getAll({}, function(cookies) {
            console.log(cookies);
        });
    "#;

    let (findings, _) = analyze_javascript(code, &PathBuf::from("test.js"));

    assert!(findings.iter().any(|f|
        f.category == Category::ApiUsage &&
        f.title.contains("cookies")
    ));
}

#[test]
fn test_detect_obfuscation() {
    let code = r#"
        const secret = atob("aHR0cHM6Ly9ldmlsLmNvbQ==");
        fetch(secret);
    "#;

    let (findings, _) = analyze_javascript(code, &PathBuf::from("test.js"));

    assert!(findings.iter().any(|f| f.category == Category::Obfuscation));
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test javascript_tests`
Expected: FAIL - assertions fail (empty results)

**Step 3: Implement JavaScript analyzer with Oxc**

Modify `src/analyze/javascript.rs`:

```rust
use crate::models::{Finding, Endpoint, Severity, Category, Location, HttpMethod, EndpointContext};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast::visit::walk;
use oxc_ast::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use std::path::Path;

pub fn analyze_javascript(content: &str, path: &Path) -> (Vec<Finding>, Vec<Endpoint>) {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path).unwrap_or_default();

    let parser_ret = Parser::new(&allocator, content, source_type).parse();

    if parser_ret.panicked {
        return (vec![Finding::new(
            Severity::Info,
            Category::Obfuscation,
            "Failed to parse JavaScript",
        ).with_description("The file could not be parsed. It may be heavily obfuscated or contain syntax errors.")
        .with_location(Location { file: path.to_path_buf(), line: None, column: None })], Vec::new());
    }

    let mut visitor = JsAnalyzer::new(path, content);
    visitor.visit_program(&parser_ret.program);

    // Also do regex-based detection for things AST might miss
    let (regex_findings, regex_endpoints) = analyze_with_regex(content, path);
    visitor.findings.extend(regex_findings);
    visitor.endpoints.extend(regex_endpoints);

    (visitor.findings, visitor.endpoints)
}

struct JsAnalyzer<'a> {
    path: &'a Path,
    source: &'a str,
    findings: Vec<Finding>,
    endpoints: Vec<Endpoint>,
}

impl<'a> JsAnalyzer<'a> {
    fn new(path: &'a Path, source: &'a str) -> Self {
        Self {
            path,
            source,
            findings: Vec::new(),
            endpoints: Vec::new(),
        }
    }

    fn get_location(&self, span: oxc_span::Span) -> Location {
        let line = self.source[..span.start as usize].matches('\n').count() + 1;
        Location {
            file: self.path.to_path_buf(),
            line: Some(line),
            column: None,
        }
    }

    fn get_snippet(&self, span: oxc_span::Span) -> String {
        let start = span.start as usize;
        let end = (span.end as usize).min(self.source.len());
        let snippet = &self.source[start..end];
        if snippet.len() > 200 {
            format!("{}...", &snippet[..200])
        } else {
            snippet.to_string()
        }
    }
}

impl<'a> Visit<'a> for JsAnalyzer<'a> {
    fn visit_call_expression(&mut self, expr: &CallExpression<'a>) {
        // Check for dangerous function calls
        if let Expression::Identifier(ident) = &expr.callee {
            let name = ident.name.as_str();

            if name == "eval" {
                self.findings.push(
                    Finding::new(Severity::Critical, Category::ApiUsage, "Dangerous: eval() usage")
                        .with_description("eval() executes arbitrary code and is commonly used in malicious extensions to hide behavior.")
                        .with_location(self.get_location(expr.span))
                        .with_snippet(self.get_snippet(expr.span))
                );
            }

            if name == "Function" {
                self.findings.push(
                    Finding::new(Severity::Critical, Category::ApiUsage, "Dangerous: Function constructor")
                        .with_description("Function() constructor creates functions from strings, similar to eval().")
                        .with_location(self.get_location(expr.span))
                        .with_snippet(self.get_snippet(expr.span))
                );
            }

            if name == "fetch" {
                self.extract_fetch_endpoint(expr);
            }

            if name == "atob" {
                self.findings.push(
                    Finding::new(Severity::Medium, Category::Obfuscation, "Base64 decoding: atob()")
                        .with_description("atob() decodes Base64 strings. Often used to hide URLs or code.")
                        .with_location(self.get_location(expr.span))
                        .with_snippet(self.get_snippet(expr.span))
                );
            }
        }

        // Check for chrome.* or browser.* API calls
        if let Expression::StaticMemberExpression(member) = &expr.callee {
            let api_path = self.get_member_path(member);
            self.check_browser_api(&api_path, expr.span);
        }

        walk::walk_call_expression(self, expr);
    }

    fn visit_string_literal(&mut self, lit: &StringLiteral<'a>) {
        let value = lit.value.as_str();

        // Check for URLs
        if value.starts_with("http://") || value.starts_with("https://") {
            let location = self.get_location(lit.span);
            let context = classify_url(value);

            self.endpoints.push(
                Endpoint::new(value.to_string(), location)
                    .with_context(context)
            );
        }
    }
}

impl<'a> JsAnalyzer<'a> {
    fn get_member_path(&self, member: &StaticMemberExpression<'a>) -> String {
        let mut parts = vec![member.property.name.to_string()];
        let mut current: &Expression = &member.object;

        loop {
            match current {
                Expression::Identifier(ident) => {
                    parts.push(ident.name.to_string());
                    break;
                }
                Expression::StaticMemberExpression(m) => {
                    parts.push(m.property.name.to_string());
                    current = &m.object;
                }
                _ => break,
            }
        }

        parts.reverse();
        parts.join(".")
    }

    fn check_browser_api(&mut self, api_path: &str, span: oxc_span::Span) {
        let (severity, desc) = match api_path {
            p if p.contains("cookies.getAll") || p.contains("cookies.get") => {
                (Severity::Critical, "Accesses browser cookies. Could steal session tokens.")
            }
            p if p.contains("webRequest.onBeforeRequest") => {
                (Severity::Critical, "Intercepts all network requests. Can steal or modify data in transit.")
            }
            p if p.contains("tabs.executeScript") => {
                (Severity::Critical, "Injects scripts into pages. Can modify any website.")
            }
            p if p.contains("history.search") || p.contains("history.getVisits") => {
                (Severity::High, "Accesses browsing history. Significant privacy concern.")
            }
            p if p.contains("downloads.download") => {
                (Severity::Medium, "Can initiate downloads. Could download malicious files.")
            }
            p if p.contains("tabs.query") => {
                (Severity::Medium, "Queries open tabs. Can see URLs of all open pages.")
            }
            p if p.contains("storage.") => {
                (Severity::Low, "Accesses extension storage. Generally safe.")
            }
            _ => return,
        };

        self.findings.push(
            Finding::new(severity, Category::ApiUsage, format!("Browser API: {}", api_path))
                .with_description(desc)
                .with_location(self.get_location(span))
        );
    }

    fn extract_fetch_endpoint(&mut self, expr: &CallExpression<'a>) {
        if let Some(arg) = expr.arguments.first() {
            if let Argument::StringLiteral(lit) = arg {
                let url = lit.value.to_string();
                let location = self.get_location(expr.span);
                let mut endpoint = Endpoint::new(url.clone(), location)
                    .with_context(classify_url(&url));

                // Try to extract method from second argument
                if let Some(Argument::ObjectExpression(obj)) = expr.arguments.get(1) {
                    for prop in &obj.properties {
                        if let ObjectPropertyKind::ObjectProperty(p) = prop {
                            if let PropertyKey::StaticIdentifier(key) = &p.key {
                                if key.name.as_str() == "method" {
                                    if let Expression::StringLiteral(val) = &p.value {
                                        let method = match val.value.to_uppercase().as_str() {
                                            "GET" => HttpMethod::Get,
                                            "POST" => HttpMethod::Post,
                                            "PUT" => HttpMethod::Put,
                                            "DELETE" => HttpMethod::Delete,
                                            "PATCH" => HttpMethod::Patch,
                                            other => HttpMethod::Other(other.to_string()),
                                        };
                                        endpoint = endpoint.with_method(method);
                                    }
                                }
                            }
                        }
                    }
                }

                self.endpoints.push(endpoint);
            }
        }
    }
}

fn classify_url(url: &str) -> EndpointContext {
    let url_lower = url.to_lowercase();

    // Known analytics
    if url_lower.contains("google-analytics.com")
        || url_lower.contains("googletagmanager.com")
        || url_lower.contains("analytics.")
        || url_lower.contains("segment.io")
        || url_lower.contains("mixpanel.com")
    {
        return EndpointContext::Analytics;
    }

    // Known CDNs and safe domains
    if url_lower.contains("cdn.")
        || url_lower.contains("cloudflare.com")
        || url_lower.contains("jsdelivr.net")
        || url_lower.contains("unpkg.com")
    {
        return EndpointContext::Api;
    }

    EndpointContext::Unknown
}

fn analyze_with_regex(content: &str, path: &Path) -> (Vec<Finding>, Vec<Endpoint>) {
    let mut findings = Vec::new();
    let endpoints = Vec::new();

    // Detect hex-encoded strings
    let hex_re = Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap();
    if hex_re.find_iter(content).count() > 10 {
        findings.push(
            Finding::new(Severity::Medium, Category::Obfuscation, "Hex-encoded strings detected")
                .with_description("Multiple hex-encoded strings found. This is a common obfuscation technique.")
                .with_location(Location { file: path.to_path_buf(), line: None, column: None })
        );
    }

    // Detect String.fromCharCode patterns
    let charcode_re = Regex::new(r"String\.fromCharCode\s*\([^)]{20,}\)").unwrap();
    if charcode_re.is_match(content) {
        findings.push(
            Finding::new(Severity::Medium, Category::Obfuscation, "String.fromCharCode obfuscation")
                .with_description("Long String.fromCharCode sequences found. Often used to hide malicious strings.")
                .with_location(Location { file: path.to_path_buf(), line: None, column: None })
        );
    }

    // Detect document.cookie access
    if content.contains("document.cookie") {
        findings.push(
            Finding::new(Severity::High, Category::DataAccess, "Direct cookie access: document.cookie")
                .with_description("Directly reads/writes cookies. Can access sensitive session data.")
                .with_location(Location { file: path.to_path_buf(), line: None, column: None })
        );
    }

    (findings, endpoints)
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --test javascript_tests`
Expected: All 4 tests pass

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add JavaScript static analysis with Oxc"
```

---

## Task 8: CLI Output Formatting

**Files:**
- Create: `src/output/mod.rs`
- Create: `src/output/terminal.rs`

**Step 1: Create output module**

Create `src/output/mod.rs`:

```rust
pub mod terminal;

pub use terminal::print_analysis_result;
```

**Step 2: Create terminal output formatter**

Create `src/output/terminal.rs`:

```rust
use crate::models::{Extension, Finding, Endpoint, Severity, EndpointContext};
use crate::analyze::AnalysisResult;
use colored::*;

pub fn print_analysis_result(extension: &Extension, result: &AnalysisResult) {
    print_header(extension);
    print_permissions_section(&result.findings);
    print_code_findings_section(&result.findings);
    print_endpoints_section(&result.endpoints);

    if let Some(ref summary) = result.llm_summary {
        print_llm_summary(summary);
    }
}

fn print_header(extension: &Extension) {
    println!("{}", "┌─────────────────────────────────────────────────────────────┐".bright_black());

    let name = extension.name.as_deref().unwrap_or("Unknown Extension");
    println!("│  Extension: {:<48}│", name.bold());
    println!("│  ID: {:<55}│", extension.id);

    let version = extension.version.as_deref().unwrap_or("?");
    let manifest_v = extension.manifest.as_ref()
        .and_then(|m| m.manifest_version)
        .map(|v| format!("Manifest V{}", v))
        .unwrap_or_else(|| "?".to_string());
    let source = format!("{:?}", extension.source);

    println!("│  Version: {} │ {} │ {:<26}│", version, manifest_v, source);
    println!("{}", "└─────────────────────────────────────────────────────────────┘".bright_black());
    println!();
}

fn print_permissions_section(findings: &[Finding]) {
    let permission_findings: Vec<_> = findings.iter()
        .filter(|f| matches!(f.category, crate::models::Category::Permission))
        .collect();

    if permission_findings.is_empty() {
        return;
    }

    println!("{}", "── Permissions ──────────────────────────────────────────────".bright_black());

    for finding in permission_findings {
        print_finding(finding);
    }

    println!();
}

fn print_code_findings_section(findings: &[Finding]) {
    let code_findings: Vec<_> = findings.iter()
        .filter(|f| !matches!(f.category, crate::models::Category::Permission))
        .collect();

    if code_findings.is_empty() {
        return;
    }

    println!("{}", "── Code Findings ────────────────────────────────────────────".bright_black());

    for finding in code_findings {
        print_finding(finding);
    }

    println!();
}

fn print_finding(finding: &Finding) {
    let (icon, severity_colored) = match finding.severity {
        Severity::Critical => ("✖".red(), finding.severity.as_str().red().bold()),
        Severity::High => ("⚠".red(), finding.severity.as_str().red()),
        Severity::Medium => ("⚠".yellow(), finding.severity.as_str().yellow()),
        Severity::Low => ("●".blue(), finding.severity.as_str().blue()),
        Severity::Info => ("ℹ".bright_black(), finding.severity.as_str().bright_black()),
    };

    let location = finding.location.as_ref()
        .map(|l| l.to_string())
        .unwrap_or_default();

    println!("  {} {:8}  {:<30} {}", icon, severity_colored, finding.title, location.bright_black());

    if !finding.description.is_empty() {
        for line in textwrap::wrap(&finding.description, 58) {
            println!("            {}", line.bright_black());
        }
    }

    if let Some(ref snippet) = finding.code_snippet {
        println!();
        for line in snippet.lines().take(3) {
            println!("              │ {}", line.bright_cyan());
        }
    }

    println!();
}

fn print_endpoints_section(endpoints: &[Endpoint]) {
    if endpoints.is_empty() {
        return;
    }

    println!("{}", "── Network Endpoints ────────────────────────────────────────".bright_black());

    for endpoint in endpoints {
        let method = endpoint.method.as_ref()
            .map(|m| m.as_str())
            .unwrap_or("GET");

        let arrow = "→".bright_black();
        println!("  {} {} {}", arrow, method.cyan(), endpoint.url);

        if !endpoint.payload_fields.is_empty() {
            println!("    Payload: {{ {} }}", endpoint.payload_fields.join(", ").yellow());
        }

        let context_colored = match endpoint.context {
            EndpointContext::Suspicious => format!("SUSPICIOUS").red(),
            EndpointContext::KnownMalicious => format!("MALICIOUS").red().bold(),
            EndpointContext::Analytics => format!("ANALYTICS").yellow(),
            EndpointContext::Telemetry => format!("TELEMETRY").yellow(),
            EndpointContext::Api => format!("API").green(),
            EndpointContext::Unknown => format!("UNKNOWN").bright_black(),
        };

        println!("    Context: {}", context_colored);

        if let Some(ref desc) = endpoint.description {
            println!("    {}", desc.bright_black());
        }

        println!();
    }
}

fn print_llm_summary(summary: &str) {
    println!("{}", "── LLM Summary ──────────────────────────────────────────────".bright_black());

    for line in textwrap::wrap(summary, 60) {
        println!("  {}", line);
    }

    println!();
}
```

**Step 3: Add textwrap dependency**

Add to `[dependencies]` in Cargo.toml:
```toml
textwrap = "0.16"
```

**Step 4: Update lib.rs**

```rust
pub mod input;
pub mod download;
pub mod unpack;
pub mod analyze;
pub mod output;
pub mod models;

pub use models::*;
```

**Step 5: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add colored terminal output formatting"
```

---

## Task 9: LLM Integration with Rig

**Files:**
- Create: `src/llm/mod.rs`
- Create: `src/llm/provider.rs`
- Create: `src/llm/agents.rs`

**Step 1: Create LLM module**

Create `src/llm/mod.rs`:

```rust
pub mod provider;
pub mod agents;

pub use provider::{LlmProvider, create_provider};
pub use agents::{analyze_with_llm, AnalysisTask};
```

**Step 2: Create provider abstraction**

Create `src/llm/provider.rs`:

```rust
use anyhow::Result;
use rig::providers::{anthropic, openai};
use rig::completion::Chat;

#[derive(Debug, Clone)]
pub enum LlmProvider {
    OpenAi,
    Anthropic,
    Gemini,
    Ollama,
}

impl LlmProvider {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "openai" => Ok(LlmProvider::OpenAi),
            "anthropic" => Ok(LlmProvider::Anthropic),
            "gemini" => Ok(LlmProvider::Gemini),
            "ollama" => Ok(LlmProvider::Ollama),
            _ => anyhow::bail!("Unknown LLM provider: {}", s),
        }
    }
}

pub enum LlmClient {
    OpenAi(openai::Client),
    Anthropic(anthropic::Client),
    // Gemini and Ollama will need additional setup
}

pub fn create_provider(provider: &LlmProvider) -> Result<LlmClient> {
    match provider {
        LlmProvider::OpenAi => {
            let client = openai::Client::from_env();
            Ok(LlmClient::OpenAi(client))
        }
        LlmProvider::Anthropic => {
            let client = anthropic::Client::from_env();
            Ok(LlmClient::Anthropic(client))
        }
        LlmProvider::Gemini => {
            anyhow::bail!("Gemini support not yet implemented")
        }
        LlmProvider::Ollama => {
            anyhow::bail!("Ollama support not yet implemented")
        }
    }
}
```

**Step 3: Create agents module**

Create `src/llm/agents.rs`:

```rust
use crate::models::{Extension, Finding, Endpoint, Manifest, Severity, Category};
use crate::llm::provider::{LlmClient, LlmProvider};
use anyhow::Result;
use futures::future::join_all;
use rig::completion::Prompt;

pub enum AnalysisTask {
    ManifestReview(Manifest),
    ScriptAnalysis { content: String, filename: String },
    EndpointAnalysis(Vec<Endpoint>),
    FinalSummary { findings: Vec<Finding>, endpoints: Vec<Endpoint> },
}

pub async fn analyze_with_llm(
    extension: &Extension,
    client: &LlmClient,
    existing_findings: &[Finding],
    existing_endpoints: &[Endpoint],
) -> Result<(Vec<Finding>, String)> {
    let mut tasks = Vec::new();

    // Task 1: Analyze manifest
    if let Some(ref manifest) = extension.manifest {
        tasks.push(AnalysisTask::ManifestReview(manifest.clone()));
    }

    // Task 2-N: Analyze each JS file (up to reasonable limit)
    for file in extension.files.iter().take(10) {
        if let crate::models::FileType::JavaScript = file.file_type {
            if let Some(ref content) = file.content {
                // Skip very large files or minified files
                if content.len() < 50000 && !is_heavily_minified(content) {
                    tasks.push(AnalysisTask::ScriptAnalysis {
                        content: content.clone(),
                        filename: file.path.display().to_string(),
                    });
                }
            }
        }
    }

    // Task N+1: Analyze endpoints
    if !existing_endpoints.is_empty() {
        tasks.push(AnalysisTask::EndpointAnalysis(existing_endpoints.to_vec()));
    }

    // Run tasks in parallel
    let task_results: Vec<Result<Vec<Finding>>> = join_all(
        tasks.iter().map(|task| run_task(client, task))
    ).await;

    let mut all_findings: Vec<Finding> = task_results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect();

    // Final summary task
    let summary = generate_summary(
        client,
        existing_findings,
        &all_findings,
        existing_endpoints,
    ).await?;

    Ok((all_findings, summary))
}

async fn run_task(client: &LlmClient, task: &AnalysisTask) -> Result<Vec<Finding>> {
    let prompt = build_prompt(task);
    let response = send_prompt(client, &prompt).await?;
    parse_findings(&response)
}

fn build_prompt(task: &AnalysisTask) -> String {
    match task {
        AnalysisTask::ManifestReview(manifest) => {
            format!(
                "You are a browser extension security analyst. Analyze this manifest.json for security concerns.\n\
                Focus on: dangerous permissions, suspicious content scripts, overly broad host access.\n\
                Be concise. List specific concerns with severity (CRITICAL/HIGH/MEDIUM/LOW).\n\n\
                Manifest:\n{}\n\n\
                Format each finding as: [SEVERITY] Title: Description",
                serde_json::to_string_pretty(manifest).unwrap_or_default()
            )
        }
        AnalysisTask::ScriptAnalysis { content, filename } => {
            let truncated = if content.len() > 8000 {
                format!("{}...[truncated]", &content[..8000])
            } else {
                content.clone()
            };

            format!(
                "You are a browser extension security analyst. Analyze this JavaScript file for security issues.\n\
                Focus on: data exfiltration, obfuscation, suspicious network requests, dangerous API usage.\n\
                Be concise. List specific concerns with severity (CRITICAL/HIGH/MEDIUM/LOW).\n\n\
                File: {}\n\
                ```javascript\n{}\n```\n\n\
                Format each finding as: [SEVERITY] Title: Description",
                filename, truncated
            )
        }
        AnalysisTask::EndpointAnalysis(endpoints) => {
            let endpoints_str: Vec<String> = endpoints.iter().map(|e| {
                format!("- {} {} (payload: {:?})",
                    e.method.as_ref().map(|m| m.as_str()).unwrap_or("?"),
                    e.url,
                    e.payload_fields
                )
            }).collect();

            format!(
                "You are a browser extension security analyst. Analyze these network endpoints.\n\
                Identify: suspicious domains, data exfiltration patterns, analytics overreach.\n\
                Be concise. Explain what each endpoint likely does.\n\n\
                Endpoints:\n{}\n\n\
                Format: For each endpoint, state if it's SAFE, SUSPICIOUS, or MALICIOUS with brief reason.",
                endpoints_str.join("\n")
            )
        }
        AnalysisTask::FinalSummary { .. } => {
            // Handled separately
            String::new()
        }
    }
}

async fn generate_summary(
    client: &LlmClient,
    static_findings: &[Finding],
    llm_findings: &[Finding],
    endpoints: &[Endpoint],
) -> Result<String> {
    let findings_summary: Vec<String> = static_findings.iter()
        .chain(llm_findings.iter())
        .map(|f| format!("- [{}] {}: {}", f.severity.as_str(), f.title, f.description))
        .take(20)
        .collect();

    let endpoints_summary: Vec<String> = endpoints.iter()
        .map(|e| format!("- {} {}", e.method.as_ref().map(|m| m.as_str()).unwrap_or("?"), e.url))
        .take(10)
        .collect();

    let prompt = format!(
        "You are a browser extension security analyst. Write a 2-3 sentence summary of this extension's risk level.\n\
        Be direct about whether this extension appears safe or dangerous.\n\n\
        Key findings:\n{}\n\n\
        Network endpoints:\n{}\n\n\
        Summary:",
        findings_summary.join("\n"),
        endpoints_summary.join("\n")
    );

    send_prompt(client, &prompt).await
}

async fn send_prompt(client: &LlmClient, prompt: &str) -> Result<String> {
    match client {
        LlmClient::OpenAi(c) => {
            let model = c.agent("gpt-4o-mini").build();
            let response = model.prompt(prompt).await?;
            Ok(response)
        }
        LlmClient::Anthropic(c) => {
            let model = c.agent("claude-3-haiku-20240307").build();
            let response = model.prompt(prompt).await?;
            Ok(response)
        }
    }
}

fn parse_findings(response: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for line in response.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try to parse [SEVERITY] Title: Description format
        if let Some(finding) = parse_finding_line(line) {
            findings.push(finding);
        }
    }

    Ok(findings)
}

fn parse_finding_line(line: &str) -> Option<Finding> {
    let severity_markers = [
        ("[CRITICAL]", Severity::Critical),
        ("[HIGH]", Severity::High),
        ("[MEDIUM]", Severity::Medium),
        ("[LOW]", Severity::Low),
        ("CRITICAL:", Severity::Critical),
        ("HIGH:", Severity::High),
        ("MEDIUM:", Severity::Medium),
        ("LOW:", Severity::Low),
    ];

    for (marker, severity) in severity_markers {
        if line.contains(marker) {
            let rest = line.replace(marker, "").trim().to_string();
            let (title, desc) = if let Some(idx) = rest.find(':') {
                (rest[..idx].trim().to_string(), rest[idx+1..].trim().to_string())
            } else {
                (rest.clone(), String::new())
            };

            return Some(Finding::new(severity, Category::ApiUsage, title)
                .with_description(desc));
        }
    }

    None
}

fn is_heavily_minified(content: &str) -> bool {
    // Heuristic: if average line length is very high, it's probably minified
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return false;
    }

    let avg_line_len: usize = content.len() / lines.len().max(1);
    avg_line_len > 500
}
```

**Step 4: Update lib.rs**

```rust
pub mod input;
pub mod download;
pub mod unpack;
pub mod analyze;
pub mod llm;
pub mod output;
pub mod models;

pub use models::*;
```

**Step 5: Verify it compiles**

Run: `cargo build`
Expected: Compiles (may have warnings)

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add LLM integration with rig-core (OpenAI, Anthropic)"
```

---

## Task 10: Main CLI Integration

**Files:**
- Modify: `src/main.rs`

**Step 1: Implement full CLI flow**

Replace `src/main.rs`:

```rust
use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use std::path::PathBuf;
use tracing_subscriber;

use extanalyzer::input::{detect_input, InputType, extract_chrome_id_from_url, extract_firefox_slug_from_url};
use extanalyzer::download::{Downloader, chrome::ChromeDownloader, firefox::FirefoxDownloader};
use extanalyzer::unpack;
use extanalyzer::analyze::{self, manifest};
use extanalyzer::llm::{LlmProvider, create_provider, analyze_with_llm};
use extanalyzer::output::print_analysis_result;
use extanalyzer::models::{Extension, ExtensionSource, ExtensionFile, FileType};

#[derive(Parser, Debug)]
#[command(name = "extanalyzer")]
#[command(about = "Analyze Chrome and Firefox browser extensions for security issues")]
#[command(version)]
struct Args {
    /// Extension ID, URL, or file path
    #[arg(required_unless_present = "batch")]
    input: Option<String>,

    /// Analyze as Firefox extension (auto-detected for URLs)
    #[arg(long)]
    firefox: bool,

    /// Batch file with extension IDs/URLs (one per line)
    #[arg(long)]
    batch: Option<PathBuf>,

    /// LLM provider: openai, anthropic, gemini, ollama
    #[arg(long, default_value = "openai")]
    llm: String,

    /// Skip LLM analysis (static analysis only)
    #[arg(long)]
    no_llm: bool,

    /// Keep extracted files after analysis
    #[arg(long)]
    keep_files: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("{}", "extanalyzer".bold().cyan());
    println!("{}", "Browser Extension Security Analyzer".bright_black());
    println!();

    if let Some(batch_file) = args.batch {
        let content = std::fs::read_to_string(&batch_file)
            .context("Failed to read batch file")?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Err(e) = analyze_single(&args, line).await {
                eprintln!("{} {}: {}", "Error".red(), line, e);
            }

            println!("{}", "─".repeat(65).bright_black());
        }
    } else if let Some(ref input) = args.input {
        analyze_single(&args, input).await?;
    }

    Ok(())
}

async fn analyze_single(args: &Args, input: &str) -> Result<()> {
    let input_type = if args.firefox {
        InputType::FirefoxSlug(input.to_string())
    } else {
        detect_input(input)
    };

    println!("{} {}", "Analyzing:".bright_black(), input);

    // Download or read extension
    let (data, source, id) = match &input_type {
        InputType::ChromeId(id) => {
            println!("{}", "Downloading from Chrome Web Store...".bright_black());
            let downloader = ChromeDownloader::new();
            let data = downloader.download(id).await?;
            (data, ExtensionSource::Chrome, id.clone())
        }
        InputType::ChromeUrl(url) => {
            let id = extract_chrome_id_from_url(url)
                .context("Could not extract extension ID from URL")?;
            println!("{}", "Downloading from Chrome Web Store...".bright_black());
            let downloader = ChromeDownloader::new();
            let data = downloader.download(&id).await?;
            (data, ExtensionSource::Chrome, id)
        }
        InputType::FirefoxSlug(slug) => {
            println!("{}", "Downloading from Firefox Add-ons...".bright_black());
            let downloader = FirefoxDownloader::new();
            let data = downloader.download(slug).await?;
            (data, ExtensionSource::Firefox, slug.clone())
        }
        InputType::FirefoxUrl(url) => {
            let slug = extract_firefox_slug_from_url(url)
                .context("Could not extract addon slug from URL")?;
            println!("{}", "Downloading from Firefox Add-ons...".bright_black());
            let downloader = FirefoxDownloader::new();
            let data = downloader.download(&slug).await?;
            (data, ExtensionSource::Firefox, slug)
        }
        InputType::LocalFile(path) => {
            println!("{}", "Reading local file...".bright_black());
            let data = std::fs::read(path)?;
            let source = if path.ends_with(".xpi") {
                ExtensionSource::Firefox
            } else {
                ExtensionSource::Chrome
            };
            (data, source, path.clone())
        }
        InputType::BatchFile(_) => {
            anyhow::bail!("Batch file should be handled at top level");
        }
    };

    // Extract to temp directory
    let temp_dir = tempfile::tempdir()?;
    let extract_path = temp_dir.path();

    println!("{}", "Extracting...".bright_black());
    unpack::extract(&data, extract_path)?;

    // Build extension model
    let mut extension = Extension::new(id, source);
    extension.extract_path = Some(extract_path.to_path_buf());

    // Parse manifest
    let manifest_path = extract_path.join("manifest.json");
    if manifest_path.exists() {
        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let parsed_manifest = manifest::parse_manifest(&manifest_content)?;
        extension.name = parsed_manifest.name.clone();
        extension.version = parsed_manifest.version.clone();
        extension.manifest = Some(parsed_manifest);
    }

    // Collect files
    extension.files = collect_files(extract_path)?;

    // Run static analysis
    println!("{}", "Running static analysis...".bright_black());
    let mut result = analyze::analyze_extension(&extension).await?;

    // Run LLM analysis if enabled
    if !args.no_llm {
        println!("{}", "Running LLM analysis...".bright_black());

        match LlmProvider::from_str(&args.llm) {
            Ok(provider) => {
                match create_provider(&provider) {
                    Ok(client) => {
                        match analyze_with_llm(&extension, &client, &result.findings, &result.endpoints).await {
                            Ok((llm_findings, summary)) => {
                                result.findings.extend(llm_findings);
                                result.llm_summary = Some(summary);
                            }
                            Err(e) => {
                                eprintln!("{} LLM analysis failed: {}", "Warning:".yellow(), e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("{} Could not create LLM client: {}", "Warning:".yellow(), e);
                    }
                }
            }
            Err(e) => {
                eprintln!("{} {}", "Warning:".yellow(), e);
            }
        }
    }

    // Sort findings by severity
    result.findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    println!();
    print_analysis_result(&extension, &result);

    // Cleanup
    if !args.keep_files {
        drop(temp_dir);
    } else {
        println!("{} {}", "Files kept at:".bright_black(), extract_path.display());
        // Prevent cleanup
        let _ = temp_dir.into_path();
    }

    Ok(())
}

fn collect_files(dir: &std::path::Path) -> Result<Vec<ExtensionFile>> {
    let mut files = Vec::new();

    for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let path = entry.path();
            let ext = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");

            let file_type = FileType::from_extension(ext);

            let content = if matches!(file_type, FileType::JavaScript | FileType::Json | FileType::Html) {
                std::fs::read_to_string(path).ok()
            } else {
                None
            };

            files.push(ExtensionFile {
                path: path.strip_prefix(dir).unwrap_or(path).to_path_buf(),
                content,
                file_type,
            });
        }
    }

    Ok(files)
}
```

**Step 2: Add walkdir and tempfile dependencies**

Add to `[dependencies]` in Cargo.toml:
```toml
walkdir = "2"
tempfile = "3"
```

**Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully

**Step 4: Test with a real extension**

Run: `cargo run -- --no-llm nkbihfbeogaeaoehlefnkodbefgpgknn`
Expected: Downloads MetaMask and shows analysis results

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: complete CLI integration with full analysis pipeline"
```

---

## Task 11: Final Testing & Documentation

**Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass

**Step 2: Test CLI with different inputs**

```bash
# Chrome extension by ID
cargo run -- --no-llm cjpalhdlnbpafiamejdnhcphjbkeiagm

# Firefox extension by slug
cargo run -- --firefox --no-llm ublock-origin

# With LLM (requires API key)
OPENAI_API_KEY=sk-... cargo run -- nkbihfbeogaeaoehlefnkodbefgpgknn
```

**Step 3: Build release binary**

Run: `cargo build --release`
Expected: Binary at `target/release/extanalyzer`

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete browser extension analyzer v0.1.0"
```

---

## Summary

The implementation is complete with:

1. **Input detection** - Auto-detects Chrome IDs, URLs, Firefox slugs, local files
2. **Downloading** - Chrome Web Store and Firefox Add-ons support
3. **Unpacking** - CRX3 and XPI/ZIP extraction
4. **Static analysis** - Oxc-based JavaScript AST analysis
5. **Permission analysis** - Risk assessment for manifest permissions
6. **Endpoint extraction** - Finds and classifies network requests
7. **LLM analysis** - Parallel subagent analysis with rig-core
8. **CLI output** - Colored, human-readable terminal output

Future enhancements (not in this plan):
- Gemini and Ollama LLM providers
- Sandboxed dynamic analysis
- JSON output format
- Known malicious extension database
