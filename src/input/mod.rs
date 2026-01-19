use std::path::Path;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub enum InputType {
    ChromeId(String),
    ChromeUrl(String),
    FirefoxUrl(String),
    FirefoxSlug(String),
    LocalFile(String),
    BatchFile(String),
}

pub fn detect_input(input: &str) -> InputType {
    let input = input.trim();

    // Check for local file first (ends with .crx or .xpi, or is a path)
    if input.ends_with(".crx") || input.ends_with(".xpi") {
        return InputType::LocalFile(input.to_string());
    }

    // Check for Chrome Web Store URL
    if input.contains("chromewebstore.google.com") || input.contains("chrome.google.com/webstore") {
        return InputType::ChromeUrl(input.to_string());
    }

    // Check for Firefox Add-ons URL
    if input.contains("addons.mozilla.org") {
        return InputType::FirefoxUrl(input.to_string());
    }

    // Check for Chrome extension ID (32 alphanumeric lowercase chars)
    let chrome_id_re = Regex::new(r"^[a-z]{32}$").unwrap();
    if chrome_id_re.is_match(input) {
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
    let chrome_id_re = Regex::new(r"[a-z]{32}").unwrap();
    chrome_id_re.find(url).map(|m| m.as_str().to_string())
}

pub fn extract_firefox_slug_from_url(url: &str) -> Option<String> {
    // Pattern: /addon/{slug}/ or /addon/{slug}
    let slug_re = Regex::new(r"/addon/([^/?]+)").unwrap();
    slug_re.captures(url).map(|c| c[1].to_string())
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
}
