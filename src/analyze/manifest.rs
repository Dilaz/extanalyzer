use crate::models::{Finding, Manifest, Severity, Category};
use anyhow::Result;
use std::path::Path;
use std::collections::HashMap;
use regex::Regex;

pub fn parse_manifest(json: &str) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_str(json)?;
    Ok(manifest)
}

/// Resolve __MSG_*__ placeholders in a string using the extension's _locales
pub fn resolve_i18n(value: &str, extract_path: &Path) -> String {
    if !value.contains("__MSG_") {
        return value.to_string();
    }

    let re = Regex::new(r"__MSG_(\w+)__").unwrap();

    // Try to load messages from _locales/en/messages.json first, then other locales
    let locales_to_try = ["en", "en_US", "en_GB"];
    let mut messages: Option<HashMap<String, serde_json::Value>> = None;

    for locale in locales_to_try {
        let messages_path = extract_path.join("_locales").join(locale).join("messages.json");
        if let Ok(content) = std::fs::read_to_string(&messages_path) {
            if let Ok(parsed) = serde_json::from_str(&content) {
                messages = Some(parsed);
                break;
            }
        }
    }

    // If no English locale found, try to find any locale
    if messages.is_none() {
        let locales_dir = extract_path.join("_locales");
        if let Ok(entries) = std::fs::read_dir(&locales_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let messages_path = entry.path().join("messages.json");
                    if let Ok(content) = std::fs::read_to_string(&messages_path) {
                        if let Ok(parsed) = serde_json::from_str(&content) {
                            messages = Some(parsed);
                            break;
                        }
                    }
                }
            }
        }
    }

    let Some(messages) = messages else {
        return value.to_string();
    };

    re.replace_all(value, |caps: &regex::Captures| {
        let key = &caps[1];
        // Try both exact key and lowercase key (Chrome uses case-insensitive matching)
        messages.get(key)
            .or_else(|| messages.get(&key.to_lowercase()))
            .and_then(|v| v.get("message"))
            .and_then(|m| m.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| caps[0].to_string())
    }).to_string()
}

pub fn analyze_permissions(manifest: &Manifest) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(ref permissions) = manifest.permissions {
        for perm in permissions {
            if let Some(finding) = analyze_single_permission(perm) {
                findings.push(finding);
            }
        }
    }

    if let Some(ref host_permissions) = manifest.host_permissions {
        for perm in host_permissions {
            if let Some(finding) = analyze_single_permission(perm) {
                findings.push(finding);
            }
        }
    }

    findings
}

fn analyze_single_permission(perm: &str) -> Option<Finding> {
    match perm {
        "<all_urls>" | "*://*/*" | "http://*/*" | "https://*/*" => {
            Some(Finding::new(Severity::Critical, Category::Permission, format!("Broad host access: {}", perm))
                .with_description("Can access and modify content on all websites. This is extremely powerful and commonly abused by malicious extensions."))
        }
        "webRequestBlocking" => {
            Some(Finding::new(Severity::Critical, Category::Permission, "webRequestBlocking permission")
                .with_description("Can intercept, block, and modify all network requests. Often used for data theft or ad injection."))
        }
        "cookies" => {
            Some(Finding::new(Severity::High, Category::Permission, "cookies permission")
                .with_description("Can read and modify cookies for all sites. Could be used to steal session tokens."))
        }
        "webRequest" => {
            Some(Finding::new(Severity::High, Category::Permission, "webRequest permission")
                .with_description("Can observe all network requests. Useful for monitoring but can leak browsing activity."))
        }
        "tabs" => {
            Some(Finding::new(Severity::Medium, Category::Permission, "tabs permission")
                .with_description("Can see URLs and titles of all open tabs. Could leak browsing activity."))
        }
        "history" => {
            Some(Finding::new(Severity::High, Category::Permission, "history permission")
                .with_description("Can read and modify browsing history. Significant privacy concern."))
        }
        "downloads" => {
            Some(Finding::new(Severity::Medium, Category::Permission, "downloads permission")
                .with_description("Can manage downloads. Could be used to download malicious files."))
        }
        "storage" => {
            Some(Finding::new(Severity::Low, Category::Permission, "storage permission")
                .with_description("Local storage access. Generally safe, used for storing extension settings."))
        }
        "activeTab" => {
            Some(Finding::new(Severity::Info, Category::Permission, "activeTab permission")
                .with_description("Temporary access to active tab when user invokes the extension. Safe, limited scope."))
        }
        _ if perm.starts_with("http") || perm.contains("*") => {
            Some(Finding::new(Severity::Medium, Category::Permission, format!("Host permission: {}", perm))
                .with_description(format!("Can access content on matching URLs: {}", perm)))
        }
        _ => None,
    }
}
