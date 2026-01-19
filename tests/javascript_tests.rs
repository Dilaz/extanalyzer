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
