pub mod chrome;
pub mod firefox;

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Downloader {
    async fn download(&self, id: &str) -> Result<Vec<u8>>;
}
