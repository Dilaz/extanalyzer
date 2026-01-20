use super::{Location, Severity};

/// Represents the origin of data used in network requests
#[derive(Debug, Clone, PartialEq)]
pub enum DataSource {
    /// document.cookie access, optionally with specific cookie name
    Cookie(Option<String>),
    /// localStorage.getItem(key)
    LocalStorage(String),
    /// sessionStorage.getItem(key)
    SessionStorage(String),
    /// chrome.history.search results
    BrowsingHistory,
    /// DOM element content (e.g., querySelector(...).innerText)
    DomElement(String),
    /// User input field value
    UserInput(String),
    /// location.href, location.pathname, etc.
    Location(String),
    /// Data fetched from another URL
    NetworkResponse(String),
    /// Untracked variable
    Unknown(String),
}

impl std::fmt::Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSource::Cookie(None) => write!(f, "Cookie"),
            DataSource::Cookie(Some(name)) => write!(f, "Cookie({})", name),
            DataSource::LocalStorage(key) => write!(f, "localStorage({})", key),
            DataSource::SessionStorage(key) => write!(f, "sessionStorage({})", key),
            DataSource::BrowsingHistory => write!(f, "BrowsingHistory"),
            DataSource::DomElement(selector) => write!(f, "DOM({})", selector),
            DataSource::UserInput(field) => write!(f, "UserInput({})", field),
            DataSource::Location(prop) => write!(f, "location.{}", prop),
            DataSource::NetworkResponse(url) => write!(f, "NetworkResponse({})", url),
            DataSource::Unknown(name) => write!(f, "{}", name),
        }
    }
}

/// Flags indicating suspicious characteristics of an endpoint
#[derive(Debug, Clone, PartialEq)]
pub enum EndpointFlag {
    /// Data from one domain is being sent to another
    CrossDomainTransfer { source_domain: String },
    /// Endpoint receives sensitive data (cookies, history, etc.)
    SensitiveData,
    /// Known tracking/analytics domain
    KnownTracker,
}

impl EndpointFlag {
    pub fn severity(&self) -> Severity {
        match self {
            EndpointFlag::CrossDomainTransfer { .. } => Severity::High,
            EndpointFlag::SensitiveData => Severity::High,
            EndpointFlag::KnownTracker => Severity::Medium,
        }
    }

    pub fn description(&self) -> String {
        match self {
            EndpointFlag::CrossDomainTransfer { source_domain } => {
                format!("Data from {} sent to different domain", source_domain)
            }
            EndpointFlag::SensitiveData => "Receives sensitive user data".to_string(),
            EndpointFlag::KnownTracker => "Known tracking/analytics endpoint".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Other(String),
}

impl HttpMethod {
    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Other(s) => s,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EndpointContext {
    Analytics,
    Telemetry,
    Api,
    Suspicious,
    KnownMalicious,
    Unknown,
}

impl EndpointContext {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointContext::Analytics => "ANALYTICS",
            EndpointContext::Telemetry => "TELEMETRY",
            EndpointContext::Api => "API",
            EndpointContext::Suspicious => "SUSPICIOUS",
            EndpointContext::KnownMalicious => "MALICIOUS",
            EndpointContext::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: String,
    pub method: Option<HttpMethod>,
    pub data_sources: Vec<DataSource>,
    pub location: Location,
    pub context: EndpointContext,
    pub description: Option<String>,
    pub flags: Vec<EndpointFlag>,
}

impl Endpoint {
    pub fn new(url: String, location: Location) -> Self {
        Self {
            url,
            method: None,
            data_sources: Vec::new(),
            location,
            context: EndpointContext::Unknown,
            description: None,
            flags: Vec::new(),
        }
    }

    pub fn with_method(mut self, method: HttpMethod) -> Self {
        self.method = Some(method);
        self
    }

    pub fn with_data_sources(mut self, sources: Vec<DataSource>) -> Self {
        self.data_sources = sources;
        self
    }

    pub fn with_context(mut self, context: EndpointContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_flag(mut self, flag: EndpointFlag) -> Self {
        self.flags.push(flag);
        self
    }

    /// Get the highest severity from all flags
    pub fn max_flag_severity(&self) -> Option<Severity> {
        self.flags.iter().map(|f| f.severity()).min() // min because Critical < High < Medium etc.
    }
}
