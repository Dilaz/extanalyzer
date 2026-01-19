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
