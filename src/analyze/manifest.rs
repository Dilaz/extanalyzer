use crate::models::{Finding, Manifest, Severity, Category};
use anyhow::Result;

pub fn parse_manifest(json: &str) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_str(json)?;
    Ok(manifest)
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
