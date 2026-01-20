use crate::analyze::AnalysisResult;
use crate::models::{DataSource, Endpoint, EndpointContext, EndpointFlag, Extension, Finding, Severity};
use colored::*;
use std::collections::HashMap;

pub fn print_analysis_result(extension: &Extension, result: &AnalysisResult) {
    print_header(extension);
    print_permissions_section(&result.findings);
    print_code_findings_section(&result.findings);
    print_dark_patterns_section(&result.findings);
    print_endpoints_section(&result.endpoints);

    if let Some(ref summary) = result.llm_summary {
        print_llm_summary(summary);
    }
}

fn print_header(extension: &Extension) {
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────┐".bright_black()
    );

    let name = extension.name.as_deref().unwrap_or("Unknown Extension");
    println!("│  Extension: {:<48}│", name.bold());
    println!("│  ID: {:<55}│", extension.id);

    let version = extension.version.as_deref().unwrap_or("?");
    let manifest_v = extension
        .manifest
        .as_ref()
        .and_then(|m| m.manifest_version)
        .map(|v| format!("Manifest V{}", v))
        .unwrap_or_else(|| "?".to_string());
    let source = format!("{:?}", extension.source);

    println!("│  Version: {} │ {} │ {:<26}│", version, manifest_v, source);
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────┘".bright_black()
    );
    println!();
}

fn print_permissions_section(findings: &[Finding]) {
    let permission_findings: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.category, crate::models::Category::Permission))
        .collect();

    if permission_findings.is_empty() {
        return;
    }

    println!(
        "{}",
        "── Permissions ──────────────────────────────────────────────".bright_black()
    );

    for finding in permission_findings {
        print_finding(finding);
    }

    println!();
}

fn print_code_findings_section(findings: &[Finding]) {
    let code_findings: Vec<_> = findings
        .iter()
        .filter(|f| !matches!(f.category, crate::models::Category::Permission))
        .filter(|f| !matches!(f.category, crate::models::Category::DarkPattern(_)))
        .collect();

    if code_findings.is_empty() {
        return;
    }

    println!(
        "{}",
        "── Code Findings ────────────────────────────────────────────".bright_black()
    );

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

    let location = finding
        .location
        .as_ref()
        .map(|l| l.to_string())
        .unwrap_or_default();

    println!(
        "  {} {:8}  {:<30} {}",
        icon,
        severity_colored,
        finding.title,
        location.bright_black()
    );

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

fn print_dark_patterns_section(findings: &[Finding]) {
    let dark_pattern_findings: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.category, crate::models::Category::DarkPattern(_)))
        .collect();

    if dark_pattern_findings.is_empty() {
        return;
    }

    println!(
        "{}",
        "── Dark Patterns ────────────────────────────────────────────".bright_black()
    );

    for finding in dark_pattern_findings {
        print_finding(finding);
    }

    println!();
}

fn print_endpoints_section(endpoints: &[Endpoint]) {
    if endpoints.is_empty() {
        return;
    }

    println!(
        "{}",
        "── Network Endpoints ────────────────────────────────────────".bright_black()
    );

    // Group by URL
    let mut grouped: HashMap<String, Vec<&Endpoint>> = HashMap::new();
    for endpoint in endpoints {
        grouped.entry(endpoint.url.clone()).or_default().push(endpoint);
    }

    // Sort by context severity (most suspicious first)
    let mut sorted: Vec<_> = grouped.into_iter().collect();
    sorted.sort_by(|a, b| {
        let max_a = a.1.iter().map(|e| context_severity(&e.context)).max().unwrap_or(0);
        let max_b = b.1.iter().map(|e| context_severity(&e.context)).max().unwrap_or(0);
        max_b.cmp(&max_a).then_with(|| a.0.cmp(&b.0))
    });

    for (url, endpoint_group) in sorted {
        println!();
        println!("  {}", url.white());

        // Collect unique methods with their locations
        let mut methods: HashMap<String, Vec<String>> = HashMap::new();
        let mut all_sources: Vec<DataSource> = Vec::new();
        let mut all_flags: Vec<&EndpointFlag> = Vec::new();
        let mut context = EndpointContext::Unknown;

        for ep in &endpoint_group {
            let method = ep.method.as_ref().map(|m| m.as_str()).unwrap_or("GET").to_string();
            let loc = format!("{}:{}",
                ep.location.file.file_name().and_then(|n| n.to_str()).unwrap_or("unknown"),
                ep.location.line.unwrap_or(0)
            );
            methods.entry(method).or_default().push(loc);

            for source in &ep.data_sources {
                if !all_sources.contains(source) {
                    all_sources.push(source.clone());
                }
            }

            for flag in &ep.flags {
                if !all_flags.contains(&flag) {
                    all_flags.push(flag);
                }
            }

            if context_severity(&ep.context) > context_severity(&context) {
                context = ep.context.clone();
            }
        }

        // Print methods
        for (method, locations) in &methods {
            let loc_str = if locations.len() == 1 {
                format!("({})", locations[0])
            } else {
                format!("(×{} calls)", locations.len())
            };
            println!("    {} {:<6} {}", "→".bright_black(), method.cyan(), loc_str.bright_black());
        }

        // Print data sources if any
        if !all_sources.is_empty() {
            let sources_str = all_sources.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
            println!("        Sends: {}", sources_str.yellow());
        }

        // Print flags if any
        for flag in all_flags {
            let flag_str = match flag {
                EndpointFlag::CrossDomainTransfer { source_domain } => {
                    format!("⚠ Cross-domain transfer from {}", source_domain).red().to_string()
                }
                EndpointFlag::SensitiveData => "⚠ Receives sensitive data".red().to_string(),
                EndpointFlag::KnownTracker => "● Known tracker".yellow().to_string(),
            };
            println!("        {}", flag_str);
        }

        // Print context
        let context_colored = match context {
            EndpointContext::Suspicious => "SUSPICIOUS".red(),
            EndpointContext::KnownMalicious => "MALICIOUS".red().bold(),
            EndpointContext::Analytics => "ANALYTICS".yellow(),
            EndpointContext::Telemetry => "TELEMETRY".yellow(),
            EndpointContext::Api => "API".green(),
            EndpointContext::Unknown => "UNKNOWN".bright_black(),
        };
        println!("    Context: {}", context_colored);
    }

    println!();
}

/// Get numeric severity for endpoint context (higher = more severe)
fn context_severity(context: &EndpointContext) -> u8 {
    match context {
        EndpointContext::KnownMalicious => 5,
        EndpointContext::Suspicious => 4,
        EndpointContext::Analytics => 3,
        EndpointContext::Telemetry => 2,
        EndpointContext::Api => 1,
        EndpointContext::Unknown => 0,
    }
}

fn print_llm_summary(summary: &str) {
    println!(
        "{}",
        "── LLM Summary ──────────────────────────────────────────────".bright_black()
    );
    println!();
    let skin = termimad::MadSkin::default();
    skin.print_text(summary);
    println!();
}
