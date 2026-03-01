use extanalyzer::llm::review_agent::{Verdict, apply_verdict, parse_verdict};
use extanalyzer::models::{Category, Finding, Severity};

#[test]
fn test_full_verdict_flow_confirm() {
    let finding = Finding::new(
        Severity::Medium,
        Category::Obfuscation,
        "String.fromCharCode() obfuscation detected",
    )
    .with_description("String.fromCharCode() is commonly used to obfuscate malicious code");

    let response = r#"{"action": "confirm", "reasoning": "This code constructs a URL character by character from numeric codes, likely to avoid URL detection by static analysis."}"#;
    let verdict = parse_verdict(response).unwrap();
    let result = apply_verdict(finding, verdict);

    assert!(result.is_some());
    let f = result.unwrap();
    assert!(matches!(f.severity, Severity::Medium));
    assert!(f.review_reasoning.unwrap().contains("URL detection"));
}

#[test]
fn test_full_verdict_flow_downgrade() {
    let finding = Finding::new(
        Severity::Medium,
        Category::Obfuscation,
        "String.fromCharCode() obfuscation detected",
    )
    .with_description("String.fromCharCode() is commonly used to obfuscate malicious code");

    let response = r#"{"action": "downgrade", "new_severity": "info", "reasoning": "This is a standard UTF-8 byte-to-character conversion used in the i18n module."}"#;
    let verdict = parse_verdict(response).unwrap();
    let result = apply_verdict(finding, verdict);

    assert!(result.is_some());
    let f = result.unwrap();
    assert!(matches!(f.severity, Severity::Info));
    assert!(
        f.review_reasoning
            .as_deref()
            .unwrap()
            .contains("Downgraded from MEDIUM")
    );
}

#[test]
fn test_full_verdict_flow_dismiss() {
    let finding = Finding::new(
        Severity::Medium,
        Category::Obfuscation,
        "String.fromCharCode() obfuscation detected",
    );

    let response = r#"{"action": "dismiss", "reasoning": "False positive: fromCharCode(0xff) is used to create a single byte for binary protocol handling."}"#;
    let verdict = parse_verdict(response).unwrap();
    let result = apply_verdict(finding, verdict);

    assert!(result.is_none());
}

#[test]
fn test_verdict_parsing_from_agent_response_with_surrounding_text() {
    let response = r#"After investigating, I found this is benign. {"action": "dismiss", "reasoning": "False positive"} That concludes my review."#;
    let verdict = parse_verdict(response);
    assert!(verdict.is_some());
    assert!(matches!(verdict.unwrap(), Verdict::Dismiss { .. }));
}

#[test]
fn test_verdict_parsing_fails_gracefully_on_garbage() {
    let response = "I couldn't determine the issue. Let me investigate more.";
    let verdict = parse_verdict(response);
    assert!(verdict.is_none());
}
