use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionSource {
    Chrome,
    Firefox,
    LocalFile,
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub source: ExtensionSource,
    pub manifest: Option<Manifest>,
    pub files: Vec<ExtensionFile>,
    pub extract_path: Option<PathBuf>,
}

impl Extension {
    pub fn new(id: String, source: ExtensionSource) -> Self {
        Self {
            id,
            name: None,
            version: None,
            source,
            manifest: None,
            files: Vec::new(),
            extract_path: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtensionFile {
    pub path: PathBuf,
    pub content: Option<String>,
    pub file_type: FileType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileType {
    JavaScript,
    Json,
    Html,
    Css,
    Image,
    Other,
}

impl FileType {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "js" | "mjs" | "cjs" => FileType::JavaScript,
            "json" => FileType::Json,
            "html" | "htm" => FileType::Html,
            "css" => FileType::Css,
            "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" => FileType::Image,
            _ => FileType::Other,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub name: Option<String>,
    pub version: Option<String>,
    pub manifest_version: Option<u8>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub host_permissions: Option<Vec<String>>,
    pub content_scripts: Option<Vec<ContentScript>>,
    pub background: Option<Background>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContentScript {
    pub matches: Option<Vec<String>>,
    pub js: Option<Vec<String>>,
    pub css: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Background {
    pub service_worker: Option<String>,
    pub scripts: Option<Vec<String>>,
}
