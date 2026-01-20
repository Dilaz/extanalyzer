//! Dark pattern detection rules
//!
//! This module provides static pattern-based rules for detecting dark patterns
//! in JavaScript code. It uses regex and string matching for heuristic detection.
//! Note: This does NOT do AST analysis - that's handled in javascript.rs.

use crate::models::{Category, DarkPatternType, Finding, Location, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Known affiliate network domains
#[allow(dead_code)]
const AFFILIATE_DOMAINS: &[&str] = &[
    "shareasale.com",
    "commission-junction.com",
    "cj.com",
    "linksynergy.com",
    "awin1.com",
    "impact.com",
    "partnerize.com",
    "pepperjam.com",
];

/// Known ad network domains
#[allow(dead_code)]
const AD_NETWORK_DOMAINS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "facebook.com/tr",
    "amazon-adsystem.com",
    "adnxs.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
];

/// Patterns for affiliate link injection
static AFFILIATE_PARAM_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[?&](ref|affiliate|aff|tag|utm_source)="#).unwrap()
});

/// Patterns for review nagging
static REVIEW_URL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"chrome\.google\.com/webstore/detail|addons\.mozilla\.org.*reviews"#).unwrap()
});

/// Analyze code for dark patterns
///
/// This function performs static pattern matching to detect various dark patterns
/// in JavaScript source code. The rules are heuristic-based and may have false positives.
pub fn analyze_dark_patterns(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for various dark patterns
    findings.extend(check_affiliate_injection(source, file_path));
    findings.extend(check_review_nagging(source, file_path));
    findings.extend(check_notification_spam(source, file_path));
    findings.extend(check_fingerprinting(source, file_path));

    findings
}

fn check_affiliate_injection(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for affiliate parameter injection
    for (line_num, line) in source.lines().enumerate() {
        if AFFILIATE_PARAM_PATTERN.is_match(line) && line.contains("href") {
            findings.push(
                Finding::new(
                    Severity::High,
                    Category::DarkPattern(DarkPatternType::AffiliateInjection),
                    "Potential affiliate link injection",
                )
                .with_description("Code modifies links to add affiliate tracking parameters")
                .with_location(Location {
                    file: file_path.to_path_buf(),
                    line: Some(line_num + 1),
                    column: None,
                }),
            );
        }
    }

    findings
}

fn check_review_nagging(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for setUninstallURL with review links
    if source.contains("setUninstallURL") && REVIEW_URL_PATTERN.is_match(source) {
        findings.push(
            Finding::new(
                Severity::Medium,
                Category::DarkPattern(DarkPatternType::ReviewNagging),
                "Review nagging on uninstall",
            )
            .with_description("Extension prompts for review when uninstalled")
            .with_location(Location {
                file: file_path.to_path_buf(),
                line: None,
                column: None,
            }),
        );
    }

    findings
}

fn check_notification_spam(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for notification creation in loops or with short intervals
    if source.contains("notifications.create") {
        // Look for setInterval with notifications
        if source.contains("setInterval") && source.contains("notification") {
            findings.push(
                Finding::new(
                    Severity::Medium,
                    Category::DarkPattern(DarkPatternType::NotificationSpam),
                    "Potential notification spam",
                )
                .with_description("Extension may send repeated notifications")
                .with_location(Location {
                    file: file_path.to_path_buf(),
                    line: None,
                    column: None,
                }),
            );
        }
    }

    findings
}

fn check_fingerprinting(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    let fingerprint_apis = [
        ("canvas", "getContext", "Canvas fingerprinting"),
        ("webgl", "getParameter", "WebGL fingerprinting"),
        ("AudioContext", "createOscillator", "Audio fingerprinting"),
    ];

    for (api1, api2, description) in fingerprint_apis {
        if source.contains(api1) && source.contains(api2) {
            findings.push(
                Finding::new(
                    Severity::High,
                    Category::DarkPattern(DarkPatternType::Fingerprinting),
                    description,
                )
                .with_description(format!(
                    "Extension may be using {} for user tracking",
                    api1
                ))
                .with_location(Location {
                    file: file_path.to_path_buf(),
                    line: None,
                    column: None,
                }),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_affiliate_injection_detection() {
        let source = r#"
            element.href = url + "?ref=affiliate123";
        "#;
        let findings = analyze_dark_patterns(source, Path::new("test.js"));
        assert!(findings
            .iter()
            .any(|f| matches!(
                &f.category,
                Category::DarkPattern(DarkPatternType::AffiliateInjection)
            )));
    }

    #[test]
    fn test_review_nagging_detection() {
        let source = r#"
            chrome.runtime.setUninstallURL("https://chrome.google.com/webstore/detail/myext/reviews");
        "#;
        let findings = analyze_dark_patterns(source, Path::new("test.js"));
        assert!(findings
            .iter()
            .any(|f| matches!(
                &f.category,
                Category::DarkPattern(DarkPatternType::ReviewNagging)
            )));
    }

    #[test]
    fn test_notification_spam_detection() {
        let source = r#"
            setInterval(() => {
                chrome.notifications.create("alert", {
                    title: "Check this out!"
                });
            }, 60000);
        "#;
        let findings = analyze_dark_patterns(source, Path::new("test.js"));
        assert!(findings
            .iter()
            .any(|f| matches!(
                &f.category,
                Category::DarkPattern(DarkPatternType::NotificationSpam)
            )));
    }

    #[test]
    fn test_canvas_fingerprinting_detection() {
        let source = r#"
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.fillText('test', 0, 0);
            const data = canvas.toDataURL();
        "#;
        let findings = analyze_dark_patterns(source, Path::new("test.js"));
        assert!(findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::Fingerprinting)
        ) && f.title == "Canvas fingerprinting"));
    }

    #[test]
    fn test_webgl_fingerprinting_detection() {
        let source = r#"
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            const renderer = gl.getParameter(gl.RENDERER);
        "#;
        let findings = analyze_dark_patterns(source, Path::new("test.js"));
        assert!(findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::Fingerprinting)
        ) && f.title == "WebGL fingerprinting"));
    }

    #[test]
    fn test_audio_fingerprinting_detection() {
        let source = r#"
            const audioCtx = new AudioContext();
            const oscillator = audioCtx.createOscillator();
        "#;
        let findings = analyze_dark_patterns(source, Path::new("test.js"));
        assert!(findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::Fingerprinting)
        ) && f.title == "Audio fingerprinting"));
    }

    #[test]
    fn test_no_false_positives_for_clean_code() {
        let source = r#"
            function greet(name) {
                console.log("Hello, " + name);
            }
            greet("World");
        "#;
        let findings = analyze_dark_patterns(source, Path::new("test.js"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_location_line_number() {
        let source = r#"line1
line2
element.href = "?ref=test";
line4"#;
        let findings = analyze_dark_patterns(source, Path::new("test.js"));
        assert!(!findings.is_empty());
        let finding = &findings[0];
        assert_eq!(finding.location.as_ref().unwrap().line, Some(3));
    }
}
