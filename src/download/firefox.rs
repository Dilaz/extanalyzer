use super::Downloader;
use anyhow::{Context, Result};
use async_trait::async_trait;

pub struct FirefoxDownloader {
    client: reqwest::Client,
}

impl FirefoxDownloader {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0")
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    pub fn build_download_url(&self, slug: &str) -> String {
        format!(
            "https://addons.mozilla.org/firefox/downloads/latest/{}/latest.xpi",
            slug
        )
    }
}

impl Default for FirefoxDownloader {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Downloader for FirefoxDownloader {
    async fn download(&self, slug: &str) -> Result<Vec<u8>> {
        let url = self.build_download_url(slug);

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
                slug
            );
        }

        let bytes = response
            .bytes()
            .await
            .context("Failed to read response bytes")?;

        Ok(bytes.to_vec())
    }
}
