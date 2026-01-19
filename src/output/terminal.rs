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
            EndpointContext::Suspicious => "SUSPICIOUS".red(),
            EndpointContext::KnownMalicious => "MALICIOUS".red().bold(),
            EndpointContext::Analytics => "ANALYTICS".yellow(),
            EndpointContext::Telemetry => "TELEMETRY".yellow(),
            EndpointContext::Api => "API".green(),
            EndpointContext::Unknown => "UNKNOWN".bright_black(),
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
    println!();
    let skin = termimad::MadSkin::default();
    skin.print_text(summary);
    println!();
}
