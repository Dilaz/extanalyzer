use crate::models::{
    Category, DarkPatternType, DataSource, Endpoint, EndpointContext, EndpointFlag, Finding,
    HttpMethod, Location, Severity,
};
use once_cell::sync::Lazy;
use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, CallExpression, Expression, Program, Statement, StringLiteral};
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

// Lazy-compiled regex patterns for additional detection

// Pattern that looks like a regex character class (common in libraries like jQuery's Sizzle)
static REGEX_CHAR_CLASS_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\[.*\\x[0-9a-fA-F]{2}.*\]$").unwrap());

// Consecutive hex escapes indicate encoded text (suspicious) - e.g., \x68\x65\x6c\x6c\x6f
static CONSECUTIVE_HEX_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}").unwrap());
static URL_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r#"https?://[^\s"'`]+"#).unwrap());
static FROM_CHAR_CODE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"String\.fromCharCode\s*\(").unwrap());
static DOC_COOKIE_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"document\.cookie").unwrap());

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

/// JavaScript analyzer that uses Oxc to parse and walk the AST
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

    /// Extract source code snippet from a span (limited to avoid huge snippets)
    fn snippet_from_span(&self, span: oxc_span::Span) -> String {
        let start = span.start as usize;
        let end = (span.end as usize).min(self.source_text.len());
        let snippet = &self.source_text[start..end];
        // Limit snippet size to avoid overwhelming the LLM
        if snippet.len() > 500 {
            format!("{}...", &snippet[..500])
        } else {
            snippet.to_string()
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
            Expression::ComputedMemberExpression(member) => self.get_member_chain(&member.object),
            _ => None,
        }
    }

    /// Check if this call is a storage access and track it
    fn check_storage_access(&self, call_expr: &CallExpression<'_>) -> Option<DataSource> {
        if let Some(chain) = self.get_member_chain(&call_expr.callee)
            && chain.len() >= 2
        {
            let obj = &chain[0];
            let method = &chain[1];

            if method == "getItem" {
                // Get the key from first argument
                let key = call_expr
                    .arguments
                    .first()
                    .map(|arg| {
                        if let Argument::StringLiteral(lit) = arg {
                            lit.value.to_string()
                        } else {
                            "*".to_string()
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
        None
    }

    /// Check if expression is document.cookie access
    fn check_cookie_access(&self, expr: &Expression<'_>) -> Option<DataSource> {
        if let Some(chain) = self.get_member_chain(expr)
            && chain.len() == 2
            && chain[0] == "document"
            && chain[1] == "cookie"
        {
            return Some(DataSource::Cookie(None));
        }
        None
    }

    /// Check if expression is a location.* access (location.href, window.location.href, etc.)
    fn check_location_access(&self, expr: &Expression<'_>) -> Option<DataSource> {
        if let Some(chain) = self.get_member_chain(expr) {
            // Handle both "location.href" and "window.location.href"
            if chain.len() >= 2 {
                let first = &chain[0];
                // Direct location access: location.href
                if first == "location" {
                    let prop = chain.last().unwrap();
                    if ["href", "pathname", "search", "hash", "hostname", "origin"]
                        .contains(&prop.as_str())
                    {
                        return Some(DataSource::Location(prop.clone()));
                    }
                }
                // window.location access: window.location.href
                if first == "window" && chain.len() >= 3 && chain[1] == "location" {
                    let prop = chain.last().unwrap();
                    if ["href", "pathname", "search", "hash", "hostname", "origin"]
                        .contains(&prop.as_str())
                    {
                        return Some(DataSource::Location(prop.clone()));
                    }
                }
            }
        }
        None
    }

    /// Check if this call is a chrome.history.search or browser.history.search
    fn check_history_access(&self, call_expr: &CallExpression<'_>) -> Option<DataSource> {
        if let Some(chain) = self.get_member_chain(&call_expr.callee)
            && chain.len() >= 3
        {
            let is_chrome_or_browser = chain[0] == "chrome" || chain[0] == "browser";
            if is_chrome_or_browser && chain[1] == "history" && chain[2] == "search" {
                return Some(DataSource::BrowsingHistory);
            }
        }
        None
    }

    /// Check if expression is a DOM access that returns user input or DOM content
    /// e.g., document.getElementById('x').value -> UserInput("x")
    /// e.g., document.querySelector('.x').innerText -> DomElement(".x")
    fn check_dom_access(&self, expr: &Expression<'_>) -> Option<DataSource> {
        // Check for document.getElementById('x').value pattern
        if let Expression::StaticMemberExpression(member) = expr {
            // Check for .value (user input)
            if member.property.name == "value"
                && let Expression::CallExpression(call) = &member.object
                && let Some(chain) = self.get_member_chain(&call.callee)
                && chain == ["document", "getElementById"]
                && let Some(Argument::StringLiteral(lit)) = call.arguments.first()
            {
                return Some(DataSource::UserInput(lit.value.to_string()));
            }

            // Check for .innerText or .textContent (DOM content)
            if (member.property.name == "innerText" || member.property.name == "textContent")
                && let Expression::CallExpression(call) = &member.object
                && let Some(chain) = self.get_member_chain(&call.callee)
                && (chain == ["document", "querySelector"]
                    || chain == ["document", "querySelectorAll"])
                && let Some(Argument::StringLiteral(lit)) = call.arguments.first()
            {
                return Some(DataSource::DomElement(lit.value.to_string()));
            }
        }
        None
    }

    /// Check if this is a fetch() call and return the URL
    fn check_fetch_call_url(&self, call_expr: &CallExpression<'_>) -> Option<String> {
        if let Some(name) = self.get_callee_name(&call_expr.callee)
            && name == "fetch"
            && let Some(first_arg) = call_expr.arguments.first()
        {
            if let Argument::StringLiteral(lit) = first_arg {
                return Some(lit.value.to_string());
            }
            if let Argument::TemplateLiteral(tmpl) = first_arg {
                return tmpl.quasis.first().map(|q| q.value.raw.to_string());
            }
        }
        None
    }

    /// Check if this is a response.json() or response.text() call and return the variable name
    fn check_response_method_call(&self, call_expr: &CallExpression<'_>) -> Option<String> {
        if let Some(chain) = self.get_member_chain(&call_expr.callee)
            && chain.len() == 2
        {
            let obj_name = &chain[0];
            let method = &chain[1];
            if method == "json" || method == "text" {
                return Some(obj_name.clone());
            }
        }
        None
    }

    /// Extract data sources from an expression (variable reference, object, etc.)
    fn extract_data_sources(&self, expr: &Expression<'_>) -> Vec<DataSource> {
        match expr {
            Expression::Identifier(ident) => self.source_tracker.lookup(&ident.name),
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
                if let Some(chain) = self.get_member_chain(&call.callee)
                    && chain == ["JSON", "stringify"]
                    && let Some(arg) = call.arguments.first()
                    && let Some(expr) = arg.as_expression()
                {
                    return self.extract_data_sources(expr);
                }
                Vec::new()
            }
            _ => Vec::new(),
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
                        // Check if init is a call expression that returns a data source
                        if let Expression::CallExpression(call_expr) = init {
                            // Try storage first, then history
                            let source = self
                                .check_storage_access(call_expr)
                                .or_else(|| self.check_history_access(call_expr));

                            if let Some(source) = source
                                && let oxc_ast::ast::BindingPattern::BindingIdentifier(ident) =
                                    &decl.id
                            {
                                self.source_tracker.bind(&ident.name, vec![source]);
                            }
                        }
                        // Check for AwaitExpression wrapping a CallExpression
                        if let Expression::AwaitExpression(await_expr) = init
                            && let Expression::CallExpression(call_expr) = &await_expr.argument
                        {
                            let source = self
                                .check_storage_access(call_expr)
                                .or_else(|| self.check_history_access(call_expr));

                            if let Some(source) = source
                                && let oxc_ast::ast::BindingPattern::BindingIdentifier(ident) =
                                    &decl.id
                            {
                                self.source_tracker.bind(&ident.name, vec![source]);
                            }

                            // Check for fetch() call - track the response variable
                            if let Some(url) = self.check_fetch_call_url(call_expr)
                                && let oxc_ast::ast::BindingPattern::BindingIdentifier(ident) =
                                    &decl.id
                            {
                                let domain = extract_domain(&url);
                                self.source_tracker
                                    .bind(&ident.name, vec![DataSource::NetworkResponse(domain)]);
                            }

                            // Check for response.json() or response.text() - propagate source
                            if let Some(response_var) = self.check_response_method_call(call_expr)
                                && let oxc_ast::ast::BindingPattern::BindingIdentifier(ident) =
                                    &decl.id
                            {
                                // Look up the response variable's sources and propagate them
                                let sources = self.source_tracker.lookup(&response_var);
                                // Filter to only NetworkResponse sources
                                let network_sources: Vec<_> = sources
                                    .into_iter()
                                    .filter(|s| matches!(s, DataSource::NetworkResponse(_)))
                                    .collect();
                                if !network_sources.is_empty() {
                                    self.source_tracker.bind(&ident.name, network_sources);
                                }
                            }
                        }
                        // Check for member expression sources like document.cookie or location.href
                        if let Expression::StaticMemberExpression(_) = init {
                            // Try cookie, then location, then DOM access
                            let source = self
                                .check_cookie_access(init)
                                .or_else(|| self.check_location_access(init))
                                .or_else(|| self.check_dom_access(init));

                            if let Some(source) = source
                                && let oxc_ast::ast::BindingPattern::BindingIdentifier(ident) =
                                    &decl.id
                            {
                                self.source_tracker.bind(&ident.name, vec![source]);
                            }
                        }
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
                if let Some(oxc_ast::ast::ForStatementInit::VariableDeclaration(var_decl)) =
                    &for_stmt.init
                {
                    for decl in &var_decl.declarations {
                        if let Some(ref init_expr) = decl.init {
                            self.visit_expression(init_expr);
                        }
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
            Statement::ClassDeclaration(class_decl) => {
                // Visit class body methods and properties
                for element in &class_decl.body.body {
                    if let oxc_ast::ast::ClassElement::MethodDefinition(method) = element
                        && let Some(ref body) = method.value.body
                    {
                        for stmt in &body.statements {
                            self.visit_statement(stmt);
                        }
                    }
                }
            }
            Statement::SwitchStatement(switch_stmt) => {
                self.visit_expression(&switch_stmt.discriminant);
                for case in &switch_stmt.cases {
                    if let Some(ref test) = case.test {
                        self.visit_expression(test);
                    }
                    for stmt in &case.consequent {
                        self.visit_statement(stmt);
                    }
                }
            }
            Statement::DoWhileStatement(do_while) => {
                self.visit_statement(&do_while.body);
                self.visit_expression(&do_while.test);
            }
            Statement::ForInStatement(for_in) => {
                self.visit_statement(&for_in.body);
            }
            Statement::ForOfStatement(for_of) => {
                self.visit_statement(&for_of.body);
            }
            Statement::ExportDefaultDeclaration(export_default) => {
                match &export_default.declaration {
                    oxc_ast::ast::ExportDefaultDeclarationKind::FunctionDeclaration(func) => {
                        if let Some(ref body) = func.body {
                            for stmt in &body.statements {
                                self.visit_statement(stmt);
                            }
                        }
                    }
                    oxc_ast::ast::ExportDefaultDeclarationKind::ClassDeclaration(class_decl) => {
                        for element in &class_decl.body.body {
                            if let oxc_ast::ast::ClassElement::MethodDefinition(method) = element
                                && let Some(ref body) = method.value.body
                            {
                                for stmt in &body.statements {
                                    self.visit_statement(stmt);
                                }
                            }
                        }
                    }
                    _ => {
                        // Handle expression exports (e.g., export default () => {})
                        if let Some(expr) = export_default.declaration.as_expression() {
                            self.visit_expression(expr);
                        }
                    }
                }
            }
            Statement::ExportNamedDeclaration(export_named) => {
                if let Some(ref decl) = export_named.declaration {
                    match decl {
                        oxc_ast::ast::Declaration::VariableDeclaration(var_decl) => {
                            for decl in &var_decl.declarations {
                                if let Some(ref init) = decl.init {
                                    self.visit_expression(init);
                                }
                            }
                        }
                        oxc_ast::ast::Declaration::FunctionDeclaration(func) => {
                            if let Some(ref body) = func.body {
                                for stmt in &body.statements {
                                    self.visit_statement(stmt);
                                }
                            }
                        }
                        oxc_ast::ast::Declaration::ClassDeclaration(class_decl) => {
                            for element in &class_decl.body.body {
                                if let oxc_ast::ast::ClassElement::MethodDefinition(method) =
                                    element
                                    && let Some(ref body) = method.value.body
                                {
                                    for stmt in &body.statements {
                                        self.visit_statement(stmt);
                                    }
                                }
                            }
                        }
                        _ => {}
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
                        let endpoint =
                            Endpoint::new(url.clone(), self.location_from_span(quasi.span))
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
                // Check for new Function("code")
                if let Expression::Identifier(ident) = &new_expr.callee
                    && ident.name == "Function"
                {
                    self.findings.push(
                        Finding::new(
                            Severity::Critical,
                            Category::ApiUsage,
                            "Dangerous: new Function() constructor",
                        )
                        .with_description(
                            "new Function() creates functions from strings, similar to eval().",
                        )
                        .with_location(self.location_from_span(new_expr.span)),
                    );
                }
                // Continue traversing
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
        let url = if let Some(first_arg) = call_expr.arguments.first() {
            match first_arg {
                Argument::StringLiteral(lit) => Some(lit.value.to_string()),
                Argument::TemplateLiteral(tmpl) => {
                    tmpl.quasis.first().map(|q| q.value.raw.to_string())
                }
                _ => None,
            }
        } else {
            None
        };

        let Some(url) = url else { return };

        let mut endpoint = Endpoint::new(url.clone(), self.location_from_span(call_expr.span));
        let mut data_sources = Vec::new();

        if call_expr.arguments.len() > 1 {
            if let Some(Argument::ObjectExpression(opts)) = call_expr.arguments.get(1) {
                for prop in &opts.properties {
                    if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(prop) = prop {
                        let key = match &prop.key {
                            oxc_ast::ast::PropertyKey::StaticIdentifier(ident) => {
                                Some(ident.name.as_str())
                            }
                            _ => None,
                        };

                        match key {
                            Some("method") => {
                                if let Expression::StringLiteral(lit) = &prop.value {
                                    endpoint = endpoint.with_method(
                                        match lit.value.to_uppercase().as_str() {
                                            "GET" => HttpMethod::Get,
                                            "POST" => HttpMethod::Post,
                                            "PUT" => HttpMethod::Put,
                                            "DELETE" => HttpMethod::Delete,
                                            "PATCH" => HttpMethod::Patch,
                                            other => HttpMethod::Other(other.to_string()),
                                        },
                                    );
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

        let mut endpoint = endpoint
            .with_data_sources(data_sources)
            .with_context(classify_url(&url));

        // Check for cross-domain data transfer
        self.check_cross_domain_transfer(&mut endpoint);

        self.endpoints.push(endpoint);
    }

    /// Check if endpoint receives data from a different domain and flag it
    fn check_cross_domain_transfer(&mut self, endpoint: &mut Endpoint) {
        let target_domain = extract_domain(&endpoint.url);

        for source in &endpoint.data_sources {
            if let DataSource::NetworkResponse(source_domain) = source
                && source_domain != &target_domain
                && !is_same_root_domain(source_domain, &target_domain)
            {
                // Add flag to endpoint
                endpoint.flags.push(EndpointFlag::CrossDomainTransfer {
                    source_domain: source_domain.clone(),
                });

                // Create a finding
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
                    .with_location(endpoint.location.clone()),
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
            // Skip UTF-16 surrogate pair handling (common in libraries)
            if root == "String" && chain.len() >= 2 && chain[1] == "fromCharCode" {
                let snippet = self.snippet_from_span(call_expr.span);
                // Skip if it looks like UTF-16 surrogate pair handling
                let is_surrogate_handling = snippet.contains("55296")  // High surrogate start
                    || snippet.contains("56320")  // Low surrogate start
                    || snippet.contains("65536")  // Supplementary plane offset
                    || snippet.contains("0xD800") // High surrogate hex
                    || snippet.contains("0xDC00"); // Low surrogate hex

                if !is_surrogate_handling {
                    self.findings.push(
                        Finding::new(
                            Severity::Medium,
                            Category::Obfuscation,
                            "String.fromCharCode() obfuscation detected",
                        )
                        .with_description(
                            "String.fromCharCode() is commonly used to obfuscate malicious code",
                        )
                        .with_location(self.location_from_span(call_expr.span))
                        .with_snippet(snippet),
                    );
                }
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
                "proxy" => (Severity::High, "Proxy API can redirect all network traffic"),
                _ => (Severity::Info, "Browser extension API usage"),
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
        // Only flag if consecutive hex escapes (indicates text encoding, not regex patterns)
        // Skip isolated hex escapes like \x20 or \xa0 (common in regex for whitespace)
        if CONSECUTIVE_HEX_PATTERN.is_match(value) && !REGEX_CHAR_CLASS_PATTERN.is_match(value) {
            self.findings.push(
                Finding::new(
                    Severity::Medium,
                    Category::Obfuscation,
                    "Hex-encoded string detected",
                )
                .with_description("Hex-encoded strings are often used to hide malicious payloads")
                .with_location(self.location_from_span(lit.span))
                .with_snippet(self.snippet_from_span(lit.span)),
            );
        }
    }

    /// Run additional regex-based pattern detection
    fn run_regex_patterns(&mut self) {
        // Check for String.fromCharCode patterns not caught by AST
        for cap in FROM_CHAR_CODE_PATTERN.find_iter(self.source_text) {
            // Calculate line number
            let line = self.source_text[..cap.start()]
                .chars()
                .filter(|&c| c == '\n')
                .count()
                + 1;

            // Extract a snippet around the match (up to closing paren or 200 chars)
            let snippet_start = cap.start();
            let snippet_end = self.source_text[snippet_start..]
                .find(')')
                .map(|i| (snippet_start + i + 1).min(snippet_start + 200))
                .unwrap_or((snippet_start + 200).min(self.source_text.len()));
            let snippet = &self.source_text[snippet_start..snippet_end];

            // Skip UTF-16 surrogate pair handling (common in libraries)
            let is_surrogate_handling = snippet.contains("55296")
                || snippet.contains("56320")
                || snippet.contains("65536")
                || snippet.contains("0xD800")
                || snippet.contains("0xDC00");

            // Only add if not already found by AST visitor and not surrogate handling
            if !is_surrogate_handling
                && !self.findings.iter().any(|f| {
                    f.title.contains("String.fromCharCode")
                        && f.location.as_ref().map(|l| l.line) == Some(Some(line))
                })
            {
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
                    })
                    .with_snippet(snippet),
                );
            }
        }

        // Check for document.cookie access patterns
        for cap in DOC_COOKIE_PATTERN.find_iter(self.source_text) {
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

/// Extract domain from a URL
fn extract_domain(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

/// Check if two domains have the same root domain (e.g., api.google.com and mail.google.com)
fn is_same_root_domain(domain1: &str, domain2: &str) -> bool {
    let parts1: Vec<_> = domain1.split('.').collect();
    let parts2: Vec<_> = domain2.split('.').collect();

    if parts1.len() >= 2 && parts2.len() >= 2 {
        let root1 = format!(
            "{}.{}",
            parts1[parts1.len() - 2],
            parts1[parts1.len() - 1]
        );
        let root2 = format!(
            "{}.{}",
            parts2[parts2.len() - 2],
            parts2[parts2.len() - 1]
        );
        return root1 == root2;
    }
    false
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
