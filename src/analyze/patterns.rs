// Suspicious pattern definitions - will be used by JavaScript analyzer

pub const CRITICAL_APIS: &[&str] = &[
    "chrome.webRequest.onBeforeRequest",
    "chrome.cookies.getAll",
    "chrome.cookies.get",
    "chrome.tabs.executeScript",
    "browser.webRequest.onBeforeRequest",
    "browser.cookies.getAll",
    "eval",
    "Function(",
];

pub const HIGH_RISK_APIS: &[&str] = &[
    "chrome.history.search",
    "chrome.downloads.download",
    "chrome.storage.sync.get",
    "chrome.tabs.query",
    "browser.history.search",
    "browser.downloads.download",
    "document.cookie",
    "localStorage",
    "sessionStorage",
];

pub const OBFUSCATION_PATTERNS: &[&str] = &[
    "atob(",
    "btoa(",
    "String.fromCharCode",
    "charCodeAt",
    "\\x",
    "\\u00",
];
