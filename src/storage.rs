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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;

    fn test_config_with_cache(cache_dir: PathBuf) -> crate::config::Config {
        let mut config = crate::config::Config::default();
        config.storage.cache_dir = cache_dir;
        config.storage.max_cache_mb = 100;
        config
    }

    #[tokio::test]
    async fn test_exists_with_cached_file() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        let config = test_config_with_cache(cache_dir.clone());

        // Create a fake cached file
        let cid = "QmTestCid123";
        let cache_path = cache_dir.join(cid);
        fs::create_dir_all(&cache_dir).await.unwrap();
        fs::write(&cache_path, b"test content").await.unwrap();

        // Create storage with test config (without connecting to IPFS)
        let storage = IpfsStorage {
            client: IpfsClient::from_str("http://127.0.0.1:5001").unwrap(),
            cache_dir,
            max_cache_mb: 100,
        };

        assert!(storage.exists(cid).await);
        assert!(!storage.exists("QmNonExistent").await);
    }

    #[tokio::test]
    async fn test_cache_size_empty() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        fs::create_dir_all(&cache_dir).await.unwrap();

        let storage = IpfsStorage {
            client: IpfsClient::from_str("http://127.0.0.1:5001").unwrap(),
            cache_dir,
            max_cache_mb: 100,
        };

        let size = storage.cache_size().await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_cache_size_with_files() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        fs::create_dir_all(&cache_dir).await.unwrap();

        // Create some test files
        fs::write(cache_dir.join("file1"), b"test content 1").await.unwrap();
        fs::write(cache_dir.join("file2"), b"test content 2").await.unwrap();

        let storage = IpfsStorage {
            client: IpfsClient::from_str("http://127.0.0.1:5001").unwrap(),
            cache_dir,
            max_cache_mb: 100,
        };

        let size = storage.cache_size().await.unwrap();
        assert!(size > 0);
        // "test content 1" + "test content 2" = 14 + 14 = 28 bytes
        assert_eq!(size, 28);
    }

    #[tokio::test]
    async fn test_clean_cache_under_limit() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        fs::create_dir_all(&cache_dir).await.unwrap();

        // Create a small file (well under 100 MB limit)
        fs::write(cache_dir.join("small_file"), b"small content").await.unwrap();

        let storage = IpfsStorage {
            client: IpfsClient::from_str("http://127.0.0.1:5001").unwrap(),
            cache_dir,
            max_cache_mb: 100,
        };

        // Should succeed without error
        let result = storage.clean_cache().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipfs_storage_fields() {
        let storage = IpfsStorage {
            client: IpfsClient::from_str("http://127.0.0.1:5001").unwrap(),
            cache_dir: PathBuf::from("/tmp/test"),
            max_cache_mb: 1024,
        };

        assert_eq!(storage.cache_dir, PathBuf::from("/tmp/test"));
        assert_eq!(storage.max_cache_mb, 1024);
    }

    // Note: Tests that require actual IPFS connection are integration tests
    // and should be run with a local IPFS daemon

    #[tokio::test]
    async fn test_get_from_cache() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        let cid = "QmTestCachedCid";
        let content = b"cached test content";

        fs::create_dir_all(&cache_dir).await.unwrap();
        fs::write(cache_dir.join(cid), content).await.unwrap();

        let storage = IpfsStorage {
            client: IpfsClient::from_str("http://127.0.0.1:5001").unwrap(),
            cache_dir,
            max_cache_mb: 100,
        };

        // Getting from cache should work even without IPFS
        let result = storage.get(cid).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), content.to_vec());
    }
}
