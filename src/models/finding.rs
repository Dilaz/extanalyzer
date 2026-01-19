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

#[derive(Debug, Clone, PartialEq)]
pub enum Category {
    Permission,
    ApiUsage,
    Network,
    Obfuscation,
    Cryptography,
    DataAccess,
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
}
