pub mod javascript;
pub mod manifest;
pub mod patterns;

use crate::models::{Endpoint, Extension, Finding};
use anyhow::Result;

pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub endpoints: Vec<Endpoint>,
    pub llm_summary: Option<String>,
}

pub async fn analyze_extension(extension: &Extension) -> Result<AnalysisResult> {
    let mut findings = Vec::new();
    let mut endpoints = Vec::new();

    // Analyze manifest permissions
    if let Some(ref manifest) = extension.manifest {
        findings.extend(manifest::analyze_permissions(manifest));
    }

    // Analyze JavaScript files
    for file in &extension.files {
        if let crate::models::FileType::JavaScript = file.file_type
            && let Some(ref content) = file.content
        {
            let (js_findings, js_endpoints) = javascript::analyze_javascript(content, &file.path);
            findings.extend(js_findings);
            endpoints.extend(js_endpoints);
        }
    }

    Ok(AnalysisResult {
        findings,
        endpoints,
        llm_summary: None,
    })
}
