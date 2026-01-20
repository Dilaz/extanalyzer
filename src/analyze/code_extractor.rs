//! Extract runnable code snippets around fetch calls for sandbox execution

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::SourceType;
use oxc_syntax::scope::ScopeFlags;
use std::path::Path;

/// Extracted code context for sandbox execution
#[derive(Debug, Clone)]
pub struct ExtractedSnippet {
    /// The runnable code
    pub code: String,
    /// Line number of the fetch call
    pub fetch_line: usize,
    /// URL being fetched (if statically known)
    pub fetch_url: Option<String>,
}

/// Extract code snippets containing fetch calls from JavaScript source
pub fn extract_fetch_snippets(source: &str, _file_path: &Path) -> Vec<ExtractedSnippet> {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(Path::new("file.js")).unwrap_or_default();
    let parser = Parser::new(&allocator, source, source_type);
    let parsed = parser.parse();

    if parsed.errors.is_empty() {
        let mut extractor = SnippetExtractor::new(source);
        extractor.visit_program(&parsed.program);
        extractor.snippets
    } else {
        Vec::new()
    }
}

struct SnippetExtractor<'a> {
    source: &'a str,
    snippets: Vec<ExtractedSnippet>,
    current_function_span: Option<oxc_span::Span>,
}

impl<'a> SnippetExtractor<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            snippets: Vec::new(),
            current_function_span: None,
        }
    }

    fn line_from_offset(&self, offset: u32) -> usize {
        self.source[..(offset as usize).min(self.source.len())]
            .chars()
            .filter(|&c| c == '\n')
            .count()
            + 1
    }

    fn extract_snippet(&self, span: oxc_span::Span) -> String {
        let start = span.start as usize;
        let end = (span.end as usize).min(self.source.len());
        self.source[start..end].to_string()
    }

    fn get_fetch_url(&self, call: &CallExpression<'_>) -> Option<String> {
        if let Some(first_arg) = call.arguments.first() {
            match first_arg {
                Argument::StringLiteral(lit) => Some(lit.value.to_string()),
                Argument::TemplateLiteral(tmpl) => {
                    tmpl.quasis.first().map(|q| q.value.raw.to_string())
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn is_fetch_call(&self, call: &CallExpression<'_>) -> bool {
        match &call.callee {
            Expression::Identifier(ident) => ident.name == "fetch",
            _ => false,
        }
    }
}

impl<'a> Visit<'a> for SnippetExtractor<'a> {
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        let prev_span = self.current_function_span;
        // Use the full function span to include the function signature (name, params)
        self.current_function_span = Some(func.span);
        walk::walk_function(self, func, flags);
        self.current_function_span = prev_span;
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        let prev_span = self.current_function_span;
        self.current_function_span = Some(arrow.span);
        walk::walk_arrow_function_expression(self, arrow);
        self.current_function_span = prev_span;
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.is_fetch_call(call) {
            let fetch_line = self.line_from_offset(call.span.start);
            let fetch_url = self.get_fetch_url(call);

            // Use enclosing function if available, otherwise use surrounding context
            let code = if let Some(func_span) = self.current_function_span {
                self.extract_snippet(func_span)
            } else {
                // No enclosing function - extract ~20 lines around the call
                let start_line = fetch_line.saturating_sub(10);
                let lines: Vec<&str> = self.source.lines().collect();
                let end_line = (fetch_line + 10).min(lines.len());
                lines[start_line..end_line].join("\n")
            };

            // Skip if code is too long (likely minified/bundled)
            if code.len() <= 5000 {
                self.snippets.push(ExtractedSnippet {
                    code,
                    fetch_line,
                    fetch_url,
                });
            }
        }
        walk::walk_call_expression(self, call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_extract_fetch_in_function() {
        let code = r#"
function sendData(data) {
    fetch("https://api.example.com/submit", {
        method: "POST",
        body: JSON.stringify(data)
    });
}
"#;
        let snippets = extract_fetch_snippets(code, &PathBuf::from("test.js"));
        assert_eq!(snippets.len(), 1);
        assert!(snippets[0].code.contains("sendData"));
        assert!(snippets[0].code.contains("fetch"));
        assert_eq!(
            snippets[0].fetch_url,
            Some("https://api.example.com/submit".to_string())
        );
    }

    #[test]
    fn test_extract_fetch_in_arrow_function() {
        let code = r#"
const submit = async (payload) => {
    await fetch("https://api.example.com/data", {
        method: "POST",
        body: payload
    });
};
"#;
        let snippets = extract_fetch_snippets(code, &PathBuf::from("test.js"));
        assert_eq!(snippets.len(), 1);
        assert!(snippets[0].code.contains("payload"));
    }

    #[test]
    fn test_extract_multiple_fetches() {
        let code = r#"
function first() { fetch("https://a.com"); }
function second() { fetch("https://b.com"); }
"#;
        let snippets = extract_fetch_snippets(code, &PathBuf::from("test.js"));
        assert_eq!(snippets.len(), 2);
    }

    #[test]
    fn test_skip_very_long_functions() {
        // Create a function with >5000 chars
        let long_body = "x".repeat(5100);
        let code = format!(
            r#"function big() {{ let x = "{}"; fetch("https://a.com"); }}"#,
            long_body
        );
        let snippets = extract_fetch_snippets(&code, &PathBuf::from("test.js"));
        assert!(snippets.is_empty());
    }

    #[test]
    fn test_top_level_fetch_uses_context() {
        let code = r#"
const url = "https://api.example.com";
fetch(url);
console.log("done");
"#;
        let snippets = extract_fetch_snippets(code, &PathBuf::from("test.js"));
        assert_eq!(snippets.len(), 1);
        // Should capture surrounding lines
        assert!(snippets[0].code.contains("const url"));
    }
}
