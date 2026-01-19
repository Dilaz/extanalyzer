use anyhow::{Context, Result};
use std::io::Cursor;
use std::path::Path;
use zip::ZipArchive;

pub fn extract_zip(data: &[u8], output_dir: &Path) -> Result<()> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)
        .context("Failed to read ZIP archive")?;

    archive.extract(output_dir)
        .context("Failed to extract ZIP contents")?;

    Ok(())
}
