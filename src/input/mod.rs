use std::path::Path;
use once_cell::sync::Lazy;
use regex::Regex;

static CHROME_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z]{32}$").unwrap());
static CHROME_ID_EXTRACT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[a-z]{32}").unwrap());
static FIREFOX_SLUG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"/addon/([^/?]+)").unwrap());

#[derive(Debug, Clone, PartialEq)]
pub enum InputType {
    ChromeId(String),
    ChromeUrl(String),
    FirefoxUrl(String),
    FirefoxSlug(String),
    LocalFile(String),
}

pub fn detect_input(input: &str) -> InputType {
    let input = input.trim();
    let input_lower = input.to_lowercase();

    // Check for local file first (ends with .crx or .xpi, or is a path)
    if input_lower.ends_with(".crx") || input_lower.ends_with(".xpi") {
        return InputType::LocalFile(input.to_string());
    }

    // Check for Chrome Web Store URL (case-insensitive)
    if input_lower.contains("chromewebstore.google.com") || input_lower.contains("chrome.google.com/webstore") {
        return InputType::ChromeUrl(input.to_string());
    }

    // Check for Firefox Add-ons URL (case-insensitive)
    if input_lower.contains("addons.mozilla.org") {
        return InputType::FirefoxUrl(input.to_string());
    }

    // Check for Chrome extension ID (32 alphanumeric lowercase chars)
    if CHROME_ID_RE.is_match(input) {
        return InputType::ChromeId(input.to_string());
    }

    // Check if it's a file path that exists
    if Path::new(input).exists() {
        return InputType::LocalFile(input.to_string());
    }

    // Default: assume Firefox slug (addon name)
    InputType::FirefoxSlug(input.to_string())
}

pub fn extract_chrome_id_from_url(url: &str) -> Option<String> {
    CHROME_ID_EXTRACT_RE.find(url).map(|m| m.as_str().to_string())
}

pub fn extract_firefox_slug_from_url(url: &str) -> Option<String> {
    // Pattern: /addon/{slug}/ or /addon/{slug}
    FIREFOX_SLUG_RE.captures(url).map(|c| c[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_chrome_id() {
        let url = "https://chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn";
        assert_eq!(
            extract_chrome_id_from_url(url),
            Some("nkbihfbeogaeaoehlefnkodbefgpgknn".to_string())
        );
    }

    #[test]
    fn test_extract_firefox_slug() {
        let url = "https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/";
        assert_eq!(
            extract_firefox_slug_from_url(url),
            Some("ublock-origin".to_string())
        );
    }

    #[test]
    fn test_uppercase_url_detection() {
        // Chrome Web Store URL with uppercase
        let chrome_url = "HTTPS://CHROMEWEBSTORE.GOOGLE.COM/detail/extension/nkbihfbeogaeaoehlefnkodbefgpgknn";
        assert_eq!(
            detect_input(chrome_url),
            InputType::ChromeUrl(chrome_url.to_string())
        );

        // Firefox Add-ons URL with mixed case
        let firefox_url = "https://ADDONS.MOZILLA.ORG/en-US/firefox/addon/ublock-origin/";
        assert_eq!(
            detect_input(firefox_url),
            InputType::FirefoxUrl(firefox_url.to_string())
        );
    }
}
