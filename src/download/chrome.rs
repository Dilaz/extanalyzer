use super::Downloader;
use anyhow::{Context, Result};
use async_trait::async_trait;

pub struct ChromeDownloader {
    client: reqwest::Client,
}

impl ChromeDownloader {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    pub fn build_download_url(&self, extension_id: &str) -> String {
        format!(
            "https://clients2.google.com/service/update2/crx?\
             response=redirect&prodversion=130.0.0.0&\
             acceptformat=crx2,crx3&x=id%3D{}%26uc",
            extension_id
        )
    }
}

impl Default for ChromeDownloader {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Downloader for ChromeDownloader {
    async fn download(&self, extension_id: &str) -> Result<Vec<u8>> {
        let url = self.build_download_url(extension_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send download request")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Download failed with status {}: {}",
                response.status(),
                extension_id
            );
        }

        let bytes = response
            .bytes()
            .await
            .context("Failed to read response bytes")?;

        Ok(bytes.to_vec())
    }
}
