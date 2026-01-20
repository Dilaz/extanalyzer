use extanalyzer::analyze::javascript::analyze_javascript;
use extanalyzer::models::{Category, Severity};
use std::path::PathBuf;

#[test]
fn test_detect_eval_usage() {
    let code = r#"
        const code = "alert('hi')";
        eval(code);
    "#;

    let (findings, _) = analyze_javascript(code, &PathBuf::from("test.js"));

    assert!(
        findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("eval"))
    );
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

    assert!(
        findings
            .iter()
            .any(|f| f.category == Category::ApiUsage && f.title.contains("cookies"))
    );
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

#[test]
fn test_data_source_display() {
    use extanalyzer::models::DataSource;

    assert_eq!(DataSource::Cookie(None).to_string(), "Cookie");
    assert_eq!(DataSource::Cookie(Some("session".into())).to_string(), "Cookie(session)");
    assert_eq!(DataSource::LocalStorage("userId".into()).to_string(), "localStorage(userId)");
    assert_eq!(DataSource::NetworkResponse("api.example.com".into()).to_string(), "NetworkResponse(api.example.com)");
}

#[test]
fn test_endpoint_flag_severity() {
    use extanalyzer::models::{EndpointFlag, Severity};

    assert_eq!(EndpointFlag::CrossDomainTransfer { source_domain: "a.com".into() }.severity(), Severity::High);
    assert_eq!(EndpointFlag::SensitiveData.severity(), Severity::High);
    assert_eq!(EndpointFlag::KnownTracker.severity(), Severity::Medium);
}

#[test]
fn test_dark_pattern_type_category() {
    use extanalyzer::models::{DarkPatternType, Category};

    let dp = DarkPatternType::AffiliateInjection;
    let cat = Category::DarkPattern(dp);
    assert_eq!(cat.as_str(), "Dark Pattern");
}

#[test]
fn test_source_tracker_local_storage() {
    let code = r#"
        let userId = localStorage.getItem('user_id');
        fetch('https://api.example.com/track', { body: userId });
    "#;

    let (findings, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    assert!(!endpoints.is_empty());
    let endpoint = endpoints.iter().find(|e| e.url.contains("api.example.com")).unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::LocalStorage(k) if k == "user_id")));
}
