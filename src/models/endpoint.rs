use super::Location;

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
    pub payload_fields: Vec<String>,
    pub location: Location,
    pub context: EndpointContext,
    pub description: Option<String>,
}

impl Endpoint {
    pub fn new(url: String, location: Location) -> Self {
        Self {
            url,
            method: None,
            payload_fields: Vec::new(),
            location,
            context: EndpointContext::Unknown,
            description: None,
        }
    }

    pub fn with_method(mut self, method: HttpMethod) -> Self {
        self.method = Some(method);
        self
    }

    pub fn with_payload(mut self, fields: Vec<String>) -> Self {
        self.payload_fields = fields;
        self
    }

    pub fn with_context(mut self, context: EndpointContext) -> Self {
        self.context = context;
        self
    }
}
