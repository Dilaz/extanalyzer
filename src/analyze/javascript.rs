use crate::models::{Category, Endpoint, EndpointContext, Finding, HttpMethod, Location, Severity};
use once_cell::sync::Lazy;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, CallExpression, Expression, Program, Statement,
    StringLiteral,
};
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use std::path::Path;

// Lazy-compiled regex patterns for additional detection
static HEX_ENCODED_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap());
static URL_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"https?://[^\s"'`]+"#).unwrap());

/// JavaScript analyzer that uses Oxc to parse and walk the AST
struct JsAnalyzer<'a> {
    findings: Vec<Finding>,
    endpoints: Vec<Endpoint>,
    source_text: &'a str,
    file_path: &'a Path,
}

impl<'a> JsAnalyzer<'a> {
    fn new(source_text: &'a str, file_path: &'a Path) -> Self {
        Self {
            findings: Vec::new(),
            endpoints: Vec::new(),
            source_text,
            file_path,
        }
    }

    /// Get line number from byte offset
    fn line_from_offset(&self, offset: u32) -> usize {
        self.source_text[..(offset as usize).min(self.source_text.len())]
            .chars()
            .filter(|&c| c == '\n')
            .count()
            + 1
    }

    /// Create a Location from a span
    fn location_from_span(&self, span: oxc_span::Span) -> Location {
        Location {
            file: self.file_path.to_path_buf(),
            line: Some(self.line_from_offset(span.start)),
            column: None,
        }
    }

    /// Extract the function name from a call expression
    fn get_callee_name(&self, callee: &Expression<'_>) -> Option<String> {
        match callee {
            Expression::Identifier(ident) => Some(ident.name.to_string()),
            _ => None,
        }
    }

    /// Extract the member expression chain (e.g., "chrome.cookies.getAll")
    fn get_member_chain(&self, expr: &Expression<'_>) -> Option<Vec<String>> {
        match expr {
            Expression::Identifier(ident) => Some(vec![ident.name.to_string()]),
            Expression::StaticMemberExpression(member) => {
                let mut chain = self.get_member_chain(&member.object)?;
                chain.push(member.property.name.to_string());
                Some(chain)
            }
            Expression::ComputedMemberExpression(member) => {
                self.get_member_chain(&member.object)
            }
            _ => None,
        }
    }

    /// Visit a program (entry point)
    fn visit_program(&mut self, program: &Program<'_>) {
        for stmt in &program.body {
            self.visit_statement(stmt);
        }
    }

    /// Visit a statement
    fn visit_statement(&mut self, stmt: &Statement<'_>) {
        match stmt {
            Statement::ExpressionStatement(expr_stmt) => {
                self.visit_expression(&expr_stmt.expression);
            }
            Statement::VariableDeclaration(var_decl) => {
                for decl in &var_decl.declarations {
                    if let Some(ref init) = decl.init {
                        self.visit_expression(init);
                    }
                }
            }
            Statement::BlockStatement(block) => {
                for stmt in &block.body {
                    self.visit_statement(stmt);
                }
            }
            Statement::IfStatement(if_stmt) => {
                self.visit_expression(&if_stmt.test);
                self.visit_statement(&if_stmt.consequent);
                if let Some(ref alt) = if_stmt.alternate {
                    self.visit_statement(alt);
                }
            }
            Statement::WhileStatement(while_stmt) => {
                self.visit_expression(&while_stmt.test);
                self.visit_statement(&while_stmt.body);
            }
            Statement::ForStatement(for_stmt) => {
                if let Some(ref init) = for_stmt.init {
                    match init {
                        oxc_ast::ast::ForStatementInit::VariableDeclaration(var_decl) => {
                            for decl in &var_decl.declarations {
                                if let Some(ref init_expr) = decl.init {
                                    self.visit_expression(init_expr);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(ref test) = for_stmt.test {
                    self.visit_expression(test);
                }
                if let Some(ref update) = for_stmt.update {
                    self.visit_expression(update);
                }
                self.visit_statement(&for_stmt.body);
            }
            Statement::FunctionDeclaration(func) => {
                if let Some(ref body) = func.body {
                    for stmt in &body.statements {
                        self.visit_statement(stmt);
                    }
                }
            }
            Statement::ReturnStatement(ret) => {
                if let Some(ref arg) = ret.argument {
                    self.visit_expression(arg);
                }
            }
            Statement::TryStatement(try_stmt) => {
                for stmt in &try_stmt.block.body {
                    self.visit_statement(stmt);
                }
                if let Some(ref handler) = try_stmt.handler {
                    for stmt in &handler.body.body {
                        self.visit_statement(stmt);
                    }
                }
                if let Some(ref finalizer) = try_stmt.finalizer {
                    for stmt in &finalizer.body {
                        self.visit_statement(stmt);
                    }
                }
            }
            _ => {}
        }
    }

    /// Visit an expression
    fn visit_expression(&mut self, expr: &Expression<'_>) {
        match expr {
            Expression::CallExpression(call_expr) => {
                self.visit_call_expression(call_expr);
            }
            Expression::StringLiteral(lit) => {
                self.visit_string_literal(lit);
            }
            Expression::ArrowFunctionExpression(arrow) => {
                // Visit arrow function body
                for stmt in &arrow.body.statements {
                    self.visit_statement(stmt);
                }
            }
            Expression::FunctionExpression(func) => {
                if let Some(ref body) = func.body {
                    for stmt in &body.statements {
                        self.visit_statement(stmt);
                    }
                }
            }
            Expression::SequenceExpression(seq) => {
                for expr in &seq.expressions {
                    self.visit_expression(expr);
                }
            }
            Expression::ConditionalExpression(cond) => {
                self.visit_expression(&cond.test);
                self.visit_expression(&cond.consequent);
                self.visit_expression(&cond.alternate);
            }
            Expression::BinaryExpression(bin) => {
                self.visit_expression(&bin.left);
                self.visit_expression(&bin.right);
            }
            Expression::LogicalExpression(log) => {
                self.visit_expression(&log.left);
                self.visit_expression(&log.right);
            }
            Expression::AssignmentExpression(assign) => {
                self.visit_expression(&assign.right);
            }
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(prop) = prop {
                        self.visit_expression(&prop.value);
                    }
                }
            }
            Expression::ArrayExpression(arr) => {
                for elem in &arr.elements {
                    if let oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) = elem {
                        self.visit_expression(&spread.argument);
                    } else if let Some(expr) = elem.as_expression() {
                        self.visit_expression(expr);
                    }
                }
            }
            Expression::TemplateLiteral(tmpl) => {
                // Check for URLs in template literal quasis
                for quasi in &tmpl.quasis {
                    let value = quasi.value.raw.as_str();
                    if let Some(url_match) = URL_PATTERN.find(value) {
                        let url = url_match.as_str().to_string();
                        let endpoint = Endpoint::new(url.clone(), self.location_from_span(quasi.span))
                            .with_context(classify_url(&url));
                        self.endpoints.push(endpoint);
                    }
                }
                for expr in &tmpl.expressions {
                    self.visit_expression(expr);
                }
            }
            Expression::StaticMemberExpression(static_member) => {
                self.visit_expression(&static_member.object);
            }
            Expression::ComputedMemberExpression(computed) => {
                self.visit_expression(&computed.object);
                self.visit_expression(&computed.expression);
            }
            Expression::PrivateFieldExpression(private) => {
                self.visit_expression(&private.object);
            }
            Expression::AwaitExpression(await_expr) => {
                self.visit_expression(&await_expr.argument);
            }
            Expression::UnaryExpression(unary) => {
                self.visit_expression(&unary.argument);
            }
            Expression::ParenthesizedExpression(paren) => {
                self.visit_expression(&paren.expression);
            }
            Expression::NewExpression(new_expr) => {
                self.visit_expression(&new_expr.callee);
                for arg in &new_expr.arguments {
                    if let Some(expr) = arg.as_expression() {
                        self.visit_expression(expr);
                    }
                }
            }
            _ => {}
        }
    }

    /// Visit a call expression
    fn visit_call_expression(&mut self, call_expr: &CallExpression<'_>) {
        // Visit callee
        self.visit_expression(&call_expr.callee);

        // Visit arguments
        for arg in &call_expr.arguments {
            if let Some(expr) = arg.as_expression() {
                self.visit_expression(expr);
            }
        }

        // Check for dangerous patterns
        self.check_dangerous_call(call_expr);
    }

    /// Visit a string literal
    fn visit_string_literal(&mut self, lit: &StringLiteral<'_>) {
        self.check_string_literal(lit);
    }

    /// Check if this is a dangerous function call
    fn check_dangerous_call(&mut self, call_expr: &CallExpression<'_>) {
        // Check for direct function calls like eval(), Function()
        if let Some(name) = self.get_callee_name(&call_expr.callee) {
            match name.as_str() {
                "eval" => {
                    self.findings.push(
                        Finding::new(
                            Severity::Critical,
                            Category::Obfuscation,
                            "Dangerous eval() call detected",
                        )
                        .with_description(
                            "eval() can execute arbitrary code and is commonly used in malicious extensions",
                        )
                        .with_location(self.location_from_span(call_expr.span)),
                    );
                }
                "Function" => {
                    self.findings.push(
                        Finding::new(
                            Severity::Critical,
                            Category::Obfuscation,
                            "Dangerous Function() constructor detected",
                        )
                        .with_description(
                            "Function() constructor can execute arbitrary code similar to eval()",
                        )
                        .with_location(self.location_from_span(call_expr.span)),
                    );
                }
                "atob" => {
                    self.findings.push(
                        Finding::new(
                            Severity::Medium,
                            Category::Obfuscation,
                            "Base64 decoding with atob() detected",
                        )
                        .with_description(
                            "atob() is often used to decode obfuscated strings or hidden URLs",
                        )
                        .with_location(self.location_from_span(call_expr.span)),
                    );
                }
                "fetch" => {
                    self.handle_fetch_call(call_expr);
                }
                _ => {}
            }
        }

        // Check for member expression calls like chrome.cookies.getAll()
        if let Some(chain) = self.get_member_chain(&call_expr.callee) {
            self.check_member_call(&chain, call_expr);
        }
    }

    /// Handle fetch() calls and extract endpoints
    fn handle_fetch_call(&mut self, call_expr: &CallExpression<'_>) {
        // Get the first argument (URL)
        if let Some(first_arg) = call_expr.arguments.first() {
            if let Argument::StringLiteral(lit) = first_arg {
                let url = lit.value.to_string();
                let mut endpoint = Endpoint::new(
                    url.clone(),
                    self.location_from_span(call_expr.span),
                );

                // Check for method in second argument (options object)
                if call_expr.arguments.len() > 1 {
                    // Default to POST if there's an options object with body
                    endpoint = endpoint.with_method(HttpMethod::Post);
                } else {
                    endpoint = endpoint.with_method(HttpMethod::Get);
                }

                // Classify the endpoint
                endpoint = endpoint.with_context(classify_url(&url));
                self.endpoints.push(endpoint);
            } else if let Argument::Identifier(ident) = first_arg {
                // Variable reference - we can't resolve it but note the fetch call
                self.findings.push(
                    Finding::new(
                        Severity::Info,
                        Category::Network,
                        format!("fetch() call with variable: {}", ident.name),
                    )
                    .with_location(self.location_from_span(call_expr.span)),
                );
            }
        }
    }

    /// Check for chrome.* and browser.* API calls
    fn check_member_call(&mut self, chain: &[String], call_expr: &CallExpression<'_>) {
        if chain.is_empty() {
            return;
        }

        let root = &chain[0];
        if root != "chrome" && root != "browser" {
            // Check for document.cookie access
            if root == "document" && chain.len() >= 2 && chain[1] == "cookie" {
                self.findings.push(
                    Finding::new(
                        Severity::High,
                        Category::DataAccess,
                        "document.cookie access detected",
                    )
                    .with_description("Direct cookie access can be used to steal session data")
                    .with_location(self.location_from_span(call_expr.span)),
                );
            }
            // Check for String.fromCharCode obfuscation
            if root == "String" && chain.len() >= 2 && chain[1] == "fromCharCode" {
                self.findings.push(
                    Finding::new(
                        Severity::Medium,
                        Category::Obfuscation,
                        "String.fromCharCode() obfuscation detected",
                    )
                    .with_description(
                        "String.fromCharCode() is commonly used to obfuscate malicious code",
                    )
                    .with_location(self.location_from_span(call_expr.span)),
                );
            }
            return;
        }

        // Handle chrome.* and browser.* APIs
        if chain.len() >= 2 {
            let api_name = &chain[1];
            let (severity, description) = match api_name.as_str() {
                "cookies" => (
                    Severity::High,
                    "Cookie access can be used to steal session data and authentication tokens",
                ),
                "webRequest" | "webRequestBlocking" => (
                    Severity::High,
                    "Web request interception can modify or steal network traffic",
                ),
                "tabs" => (
                    Severity::Medium,
                    "Tab access can be used to monitor browsing activity",
                ),
                "history" => (
                    Severity::High,
                    "History access exposes user browsing patterns",
                ),
                "bookmarks" => (
                    Severity::Medium,
                    "Bookmark access reveals user interests and saved sites",
                ),
                "downloads" => (
                    Severity::Medium,
                    "Download access can reveal sensitive files and enable malware",
                ),
                "storage" => (
                    Severity::Low,
                    "Storage API access (generally safe for extensions)",
                ),
                "runtime" => (
                    Severity::Low,
                    "Runtime API access (generally safe for extensions)",
                ),
                "scripting" | "executeScript" => (
                    Severity::High,
                    "Script execution can inject code into web pages",
                ),
                "debugger" => (
                    Severity::Critical,
                    "Debugger API can intercept and modify any page content",
                ),
                "management" => (
                    Severity::High,
                    "Extension management can disable security extensions",
                ),
                "privacy" => (
                    Severity::High,
                    "Privacy API can modify browser security settings",
                ),
                "proxy" => (
                    Severity::High,
                    "Proxy API can redirect all network traffic",
                ),
                _ => (
                    Severity::Info,
                    "Browser extension API usage",
                ),
            };

            let full_api = chain.join(".");
            self.findings.push(
                Finding::new(
                    severity,
                    Category::ApiUsage,
                    format!("{} API access: {}", root, api_name),
                )
                .with_description(description)
                .with_location(self.location_from_span(call_expr.span))
                .with_snippet(full_api),
            );
        }
    }

    /// Check string literals for URLs and obfuscation patterns
    fn check_string_literal(&mut self, lit: &StringLiteral<'_>) {
        let value = lit.value.as_str();

        // Check for URLs in strings
        if let Some(url_match) = URL_PATTERN.find(value) {
            let url = url_match.as_str().to_string();
            let endpoint = Endpoint::new(url.clone(), self.location_from_span(lit.span))
                .with_context(classify_url(&url));
            self.endpoints.push(endpoint);
        }

        // Check for hex-encoded strings (obfuscation)
        if HEX_ENCODED_PATTERN.is_match(value) {
            self.findings.push(
                Finding::new(
                    Severity::Medium,
                    Category::Obfuscation,
                    "Hex-encoded string detected",
                )
                .with_description("Hex-encoded strings are often used to hide malicious payloads")
                .with_location(self.location_from_span(lit.span)),
            );
        }
    }

    /// Run additional regex-based pattern detection
    fn run_regex_patterns(&mut self) {
        // Check for String.fromCharCode patterns not caught by AST
        let from_char_code_pattern = Regex::new(r"String\.fromCharCode\s*\(").unwrap();
        for cap in from_char_code_pattern.find_iter(self.source_text) {
            // Calculate line number
            let line = self.source_text[..cap.start()]
                .chars()
                .filter(|&c| c == '\n')
                .count()
                + 1;

            // Only add if not already found by AST visitor
            if !self.findings.iter().any(|f| {
                f.title.contains("String.fromCharCode")
                    && f.location.as_ref().map(|l| l.line) == Some(Some(line))
            }) {
                self.findings.push(
                    Finding::new(
                        Severity::Medium,
                        Category::Obfuscation,
                        "String.fromCharCode() obfuscation detected",
                    )
                    .with_description(
                        "String.fromCharCode() is commonly used to obfuscate malicious code",
                    )
                    .with_location(Location {
                        file: self.file_path.to_path_buf(),
                        line: Some(line),
                        column: None,
                    }),
                );
            }
        }

        // Check for document.cookie access patterns
        let doc_cookie_pattern = Regex::new(r"document\.cookie").unwrap();
        for cap in doc_cookie_pattern.find_iter(self.source_text) {
            let line = self.source_text[..cap.start()]
                .chars()
                .filter(|&c| c == '\n')
                .count()
                + 1;

            if !self.findings.iter().any(|f| {
                f.title.contains("document.cookie")
                    && f.location.as_ref().map(|l| l.line) == Some(Some(line))
            }) {
                self.findings.push(
                    Finding::new(
                        Severity::High,
                        Category::DataAccess,
                        "document.cookie access detected",
                    )
                    .with_description("Direct cookie access can be used to steal session data")
                    .with_location(Location {
                        file: self.file_path.to_path_buf(),
                        line: Some(line),
                        column: None,
                    }),
                );
            }
        }
    }
}

/// Classify a URL based on its domain and path
fn classify_url(url: &str) -> EndpointContext {
    let url_lower = url.to_lowercase();

    // Known analytics domains
    let analytics_domains = [
        "google-analytics.com",
        "googletagmanager.com",
        "analytics.",
        "stats.",
        "tracking.",
        "mixpanel.com",
        "segment.io",
        "amplitude.com",
    ];

    // Known suspicious patterns
    let suspicious_patterns = [
        "pastebin.com",
        "raw.githubusercontent.com",
        "gist.github.com",
        ".onion",
        "ngrok.io",
        "serveo.net",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        "discord.gg",
        "telegra.ph",
    ];

    // Check for analytics
    for domain in &analytics_domains {
        if url_lower.contains(domain) {
            return EndpointContext::Analytics;
        }
    }

    // Check for suspicious patterns
    for pattern in &suspicious_patterns {
        if url_lower.contains(pattern) {
            return EndpointContext::Suspicious;
        }
    }

    // Check for API patterns
    if url_lower.contains("/api/") || url_lower.contains("/v1/") || url_lower.contains("/v2/") {
        return EndpointContext::Api;
    }

    EndpointContext::Unknown
}

/// Analyze JavaScript code for security issues
///
/// This function parses JavaScript code using Oxc and walks the AST to detect:
/// - Dangerous function calls (eval, Function, atob)
/// - Network requests (fetch) and extracts endpoints
/// - Browser extension API usage (chrome.*, browser.*)
/// - Obfuscation patterns (hex-encoded strings, String.fromCharCode)
/// - Cookie access (document.cookie)
///
/// # Arguments
/// * `content` - The JavaScript source code to analyze
/// * `path` - The file path for reporting purposes
///
/// # Returns
/// A tuple of (findings, endpoints) discovered during analysis
pub fn analyze_javascript(content: &str, path: &Path) -> (Vec<Finding>, Vec<Endpoint>) {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path).unwrap_or_default();

    let parser_return = Parser::new(&allocator, content, source_type).parse();

    let mut analyzer = JsAnalyzer::new(content, path);

    // Walk the AST if parsing succeeded
    if !parser_return.panicked {
        analyzer.visit_program(&parser_return.program);
    }

    // Run additional regex-based pattern detection
    analyzer.run_regex_patterns();

    (analyzer.findings, analyzer.endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_classify_url_analytics() {
        assert_eq!(
            classify_url("https://www.google-analytics.com/collect"),
            EndpointContext::Analytics
        );
    }

    #[test]
    fn test_classify_url_suspicious() {
        assert_eq!(
            classify_url("https://pastebin.com/raw/abc123"),
            EndpointContext::Suspicious
        );
    }

    #[test]
    fn test_classify_url_api() {
        assert_eq!(
            classify_url("https://example.com/api/users"),
            EndpointContext::Api
        );
    }

    #[test]
    fn test_analyze_empty_code() {
        let (findings, endpoints) = analyze_javascript("", &PathBuf::from("test.js"));
        assert!(findings.is_empty());
        assert!(endpoints.is_empty());
    }
}
