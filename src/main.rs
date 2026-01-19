use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use std::path::PathBuf;

use extanalyzer::input::{detect_input, InputType, extract_chrome_id_from_url, extract_firefox_slug_from_url};
use extanalyzer::download::{Downloader, chrome::ChromeDownloader, firefox::FirefoxDownloader};
use extanalyzer::unpack;
use extanalyzer::analyze::{self, manifest::{self, resolve_i18n}};
use extanalyzer::llm::{LlmProvider, create_provider, analyze_with_llm, AnalysisTask};
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

    /// LLM model to use (defaults: gpt-4o-mini, claude-3-haiku-20240307, gemini-3-flash-preview)
    #[arg(long)]
    model: Option<String>,

    /// Skip LLM analysis (static analysis only)
    #[arg(long)]
    no_llm: bool,

    /// Keep extracted files after analysis
    #[arg(long)]
    keep_files: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("{}", "extanalyzer".bold().cyan());
    println!("{}", "Browser Extension Security Analyzer".bright_black());
    println!();

    if let Some(ref batch_file) = args.batch {
        // Batch mode
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

            println!("{}", "-".repeat(65).bright_black());
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
        // Resolve i18n placeholders like __MSG_appName__
        extension.name = parsed_manifest.name.as_ref().map(|n| resolve_i18n(n, extract_path));
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
                        let tasks = vec![
                            AnalysisTask::ManifestReview,
                            AnalysisTask::ScriptAnalysis,
                            AnalysisTask::EndpointAnalysis,
                            AnalysisTask::FinalSummary,
                        ];

                        match analyze_with_llm(&client, &extension, &result.findings, &result.endpoints, tasks, args.model.as_deref()).await {
                            Ok(llm_result) => {
                                result.findings.extend(llm_result.findings);
                                result.llm_summary = llm_result.summary;
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
        // Prevent cleanup by moving out of temp_dir
        let _ = temp_dir.keep();
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
