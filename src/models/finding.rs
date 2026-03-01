use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

/// Types of dark patterns that can be detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DarkPatternType {
    // Monetization
    AffiliateInjection,
    AdInjection,
    SearchHijacking,

    // Privacy
    HiddenTracking,
    ExcessiveCollection,
    Fingerprinting,
    DataExfiltration,

    // Manipulation
    ReviewNagging,
    NotificationSpam,
    FakeUrgency,
    DisguisedAds,

    // Bait-and-switch
    PermissionCreep,
    HiddenFunctionality,
    MisleadingDescription,
}

impl DarkPatternType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DarkPatternType::AffiliateInjection => "Affiliate Injection",
            DarkPatternType::AdInjection => "Ad Injection",
            DarkPatternType::SearchHijacking => "Search Hijacking",
            DarkPatternType::HiddenTracking => "Hidden Tracking",
            DarkPatternType::ExcessiveCollection => "Excessive Collection",
            DarkPatternType::Fingerprinting => "Fingerprinting",
            DarkPatternType::DataExfiltration => "Data Exfiltration",
            DarkPatternType::ReviewNagging => "Review Nagging",
            DarkPatternType::NotificationSpam => "Notification Spam",
            DarkPatternType::FakeUrgency => "Fake Urgency",
            DarkPatternType::DisguisedAds => "Disguised Ads",
            DarkPatternType::PermissionCreep => "Permission Creep",
            DarkPatternType::HiddenFunctionality => "Hidden Functionality",
            DarkPatternType::MisleadingDescription => "Misleading Description",
        }
    }

    pub fn category_name(&self) -> &'static str {
        match self {
            DarkPatternType::AffiliateInjection
            | DarkPatternType::AdInjection
            | DarkPatternType::SearchHijacking => "Monetization",

            DarkPatternType::HiddenTracking
            | DarkPatternType::ExcessiveCollection
            | DarkPatternType::Fingerprinting
            | DarkPatternType::DataExfiltration => "Privacy",

            DarkPatternType::ReviewNagging
            | DarkPatternType::NotificationSpam
            | DarkPatternType::FakeUrgency
            | DarkPatternType::DisguisedAds => "Manipulation",

            DarkPatternType::PermissionCreep
            | DarkPatternType::HiddenFunctionality
            | DarkPatternType::MisleadingDescription => "Bait-and-Switch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Category {
    Permission,
    ApiUsage,
    Network,
    Obfuscation,
    Cryptography,
    DataAccess,
    DarkPattern(DarkPatternType),
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Permission => "Permission",
            Category::ApiUsage => "API Usage",
            Category::Network => "Network",
            Category::Obfuscation => "Obfuscation",
            Category::Cryptography => "Cryptography",
            Category::DataAccess => "Data Access",
            Category::DarkPattern(_) => "Dark Pattern",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub file: PathBuf,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.file.display())?;
        if let Some(line) = self.line {
            write!(f, ":{}", line)?;
            if let Some(col) = self.column {
                write!(f, ":{}", col)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub description: String,
    pub location: Option<Location>,
    pub code_snippet: Option<String>,
    pub review_reasoning: Option<String>,
}

impl Finding {
    pub fn new(severity: Severity, category: Category, title: impl Into<String>) -> Self {
        Self {
            severity,
            category,
            title: title.into(),
            description: String::new(),
            location: None,
            code_snippet: None,
            review_reasoning: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.code_snippet = Some(snippet.into());
        self
    }

    pub fn with_review_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.review_reasoning = Some(reasoning.into());
        self
    }
}
