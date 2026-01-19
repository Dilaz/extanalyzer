use extanalyzer::input::{InputType, detect_input};

#[test]
fn test_detect_chrome_extension_id() {
    let input = "nkbihfbeogaeaoehlefnkodbefgpgknn";
    assert_eq!(detect_input(input), InputType::ChromeId(input.to_string()));
}

#[test]
fn test_detect_chrome_url() {
    let input = "https://chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn";
    assert!(matches!(detect_input(input), InputType::ChromeUrl(_)));
}

#[test]
fn test_detect_firefox_url() {
    let input = "https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/";
    assert!(matches!(detect_input(input), InputType::FirefoxUrl(_)));
}

#[test]
fn test_detect_local_crx() {
    let input = "./extension.crx";
    assert!(matches!(detect_input(input), InputType::LocalFile(_)));
}

#[test]
fn test_detect_local_xpi() {
    let input = "/home/user/addon.xpi";
    assert!(matches!(detect_input(input), InputType::LocalFile(_)));
}

#[test]
fn test_detect_firefox_slug() {
    // Short strings that aren't 32 chars and not a path
    let input = "ublock-origin";
    assert_eq!(detect_input(input), InputType::FirefoxSlug(input.to_string()));
}
