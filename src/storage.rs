//! IPFS storage module
//!
//! Handles model and data storage via IPFS

use anyhow::{Context, Result};
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, info};

use crate::config::Config;

/// IPFS storage client
pub struct IpfsStorage {
    client: IpfsClient,
    cache_dir: PathBuf,
    max_cache_mb: u64,
}

impl IpfsStorage {
    /// Create a new IPFS storage client
    pub async fn new(config: &Config) -> Result<Self> {
        let client = IpfsClient::from_str(&config.storage.ipfs_api)
            .context("Failed to create IPFS client")?;

        // Verify IPFS connection
        match client.version().await {
            Ok(version) => {
                info!("Connected to IPFS: {}", version.version);
            }
            Err(e) => {
                tracing::warn!("Could not connect to IPFS: {}. Running without IPFS.", e);
            }
        }

        // Ensure cache directory exists
        fs::create_dir_all(&config.storage.cache_dir).await?;

        Ok(Self {
            client,
            cache_dir: config.storage.cache_dir.clone(),
            max_cache_mb: config.storage.max_cache_mb,
        })
    }

    /// Get file from IPFS by CID
    pub async fn get(&self, cid: &str) -> Result<Vec<u8>> {
        // Check cache first
        let cache_path = self.cache_dir.join(cid);
        if cache_path.exists() {
            debug!("Cache hit for CID: {}", cid);
            return Ok(fs::read(&cache_path).await?);
        }

        // Fetch from IPFS
        info!("Fetching from IPFS: {}", cid);
        use futures::TryStreamExt;

        let data: Vec<u8> = self.client
            .cat(cid)
            .map_ok(|chunk| chunk.to_vec())
            .try_concat()
            .await?;

        // Cache the result
        fs::write(&cache_path, &data).await?;
        debug!("Cached CID: {}", cid);

        Ok(data)
    }

    /// Add file to IPFS
    pub async fn add(&self, data: Vec<u8>) -> Result<String> {
        use std::io::Cursor;

        let cursor = Cursor::new(data);
        let response = self.client.add(cursor).await?;

        info!("Added to IPFS: {}", response.hash);
        Ok(response.hash)
    }

    /// Add file from path to IPFS
    pub async fn add_file(&self, path: &PathBuf) -> Result<String> {
        let data = fs::read(path).await?;
        self.add(data).await
    }

    /// Pin a CID
    pub async fn pin(&self, cid: &str) -> Result<()> {
        self.client.pin_add(cid, true).await?;
        info!("Pinned CID: {}", cid);
        Ok(())
    }

    /// Unpin a CID
    pub async fn unpin(&self, cid: &str) -> Result<()> {
        self.client.pin_rm(cid, true).await?;
        info!("Unpinned CID: {}", cid);
        Ok(())
    }

    /// Check if CID exists locally
    pub async fn exists(&self, cid: &str) -> bool {
        let cache_path = self.cache_dir.join(cid);
        cache_path.exists()
    }

    /// Get cache size in bytes
    pub async fn cache_size(&self) -> Result<u64> {
        let mut size = 0u64;
        let mut entries = fs::read_dir(&self.cache_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            if let Ok(metadata) = entry.metadata().await {
                size += metadata.len();
            }
        }

        Ok(size)
    }

    /// Clean cache if over limit
    pub async fn clean_cache(&self) -> Result<()> {
        let size = self.cache_size().await?;
        let max_bytes = self.max_cache_mb * 1024 * 1024;

        if size > max_bytes {
            info!("Cache size {} MB exceeds limit {} MB, cleaning...",
                  size / (1024 * 1024), self.max_cache_mb);

            // TODO: Implement LRU cache eviction
            // For now, just log a warning
            tracing::warn!("Cache cleaning not yet implemented");
        }

        Ok(())
    }
}
