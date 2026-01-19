use anyhow::{Context, Result};
use std::io::Cursor;
use std::path::Path;
use zip::ZipArchive;

pub fn extract_crx(data: &[u8], output_dir: &Path) -> Result<()> {
    // CRX3 format:
    // - Magic: "Cr24" (4 bytes)
    // - Version: 3 (4 bytes, little-endian)
    // - Header length (4 bytes, little-endian)
    // - Header (protobuf, variable length)
    // - ZIP data

    if data.len() < 12 {
        anyhow::bail!("CRX file too small");
    }

    if !data.starts_with(b"Cr24") {
        anyhow::bail!("Invalid CRX magic");
    }

    let version = u32::from_le_bytes(data[4..8].try_into()?);
    if version != 3 {
        anyhow::bail!("Unsupported CRX version: {}", version);
    }

    let header_len = u32::from_le_bytes(data[8..12].try_into()?) as usize;
    let zip_start = 12 + header_len;

    if zip_start >= data.len() {
        anyhow::bail!("Invalid CRX header length");
    }

    let zip_data = &data[zip_start..];

    let cursor = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(cursor).context("Failed to read ZIP from CRX")?;

    archive
        .extract(output_dir)
        .context("Failed to extract CRX contents")?;

    Ok(())
}
