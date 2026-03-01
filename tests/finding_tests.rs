use extanalyzer::models::{Category, Finding, Severity};

#[test]
fn test_finding_review_reasoning_default_none() {
    let finding = Finding::new(Severity::Medium, Category::Obfuscation, "test");
    assert!(finding.review_reasoning.is_none());
}

#[test]
fn test_finding_with_review_reasoning() {
    let finding = Finding::new(Severity::Medium, Category::Obfuscation, "test")
        .with_review_reasoning("Downgraded: legitimate use of String.fromCharCode for i18n");
    assert_eq!(
        finding.review_reasoning.as_deref(),
        Some("Downgraded: legitimate use of String.fromCharCode for i18n")
    );
}
