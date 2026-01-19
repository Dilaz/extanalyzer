use crate::models::{Finding, Endpoint};
use std::path::Path;

pub fn analyze_javascript(_content: &str, _path: &Path) -> (Vec<Finding>, Vec<Endpoint>) {
    // Stub - will implement with Oxc in next task
    (Vec::new(), Vec::new())
}
