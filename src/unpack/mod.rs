pub mod crx;
pub mod xpi;

use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionFormat {
    Crx3,
    Zip, // XPI files are plain ZIP
    Unknown,
}

pub fn detect_format(data: &[u8]) -> ExtensionFormat {
    if data.len() < 4 {
        return ExtensionFormat::Unknown;
    }

    // CRX3 magic: "Cr24" followed by version 3
    if data.starts_with(b"Cr24") {
        return ExtensionFormat::Crx3;
    }

    // ZIP magic: "PK\x03\x04"
    if data.starts_with(b"PK\x03\x04") {
        return ExtensionFormat::Zip;
    }

    ExtensionFormat::Unknown
}

pub fn extract(data: &[u8], output_dir: &Path) -> Result<()> {
    match detect_format(data) {
        ExtensionFormat::Crx3 => crx::extract_crx(data, output_dir),
        ExtensionFormat::Zip => xpi::extract_zip(data, output_dir),
        ExtensionFormat::Unknown => anyhow::bail!("Unknown extension format"),
    }
}
