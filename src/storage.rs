//! IPFS storage module
//!
//! Handles model and data storage via IPFS.
//! Supports both local IPFS daemon and public gateways as fallback.

use anyhow::{Context, Result};
use hex;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};
use reqwest::Client as HttpClient;
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, info, warn};

use crate::config::Config;

/// Public IPFS gateways for fallback
const PUBLIC_GATEWAYS: &[&str] = &[
    "https://ipfs.io/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://dweb.link/ipfs/",
];

/// IPFS storage client
pub struct IpfsStorage {
    client: IpfsClient,
    http_client: HttpClient,
    cache_dir: PathBuf,
    max_cache_mb: u64,
    local_available: bool,
}

impl IpfsStorage {
    /// Create a new IPFS storage client
    pub async fn new(config: &Config) -> Result<Self> {
        let client = IpfsClient::from_str(&config.storage.ipfs_api)
            .context("Failed to create IPFS client")?;

        let http_client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        // Verify IPFS connection
        let local_available = match client.version().await {
            Ok(version) => {
                info!("Connected to local IPFS: {}", version.version);
                true
            }
            Err(e) => {
                warn!("Could not connect to local IPFS: {}. Will use public gateways.", e);
                false
            }
        };

        // Ensure cache directory exists
        fs::create_dir_all(&config.storage.cache_dir).await?;

        Ok(Self {
            client,
            http_client,
            cache_dir: config.storage.cache_dir.clone(),
            max_cache_mb: config.storage.max_cache_mb,
            local_available,
        })
    }

    /// Get file from IPFS by CID string
    pub async fn get_by_cid(&self, cid: &str) -> Result<Vec<u8>> {
        // Check cache first
        let cache_path = self.cache_dir.join(cid.replace("/", "_").replace(":", "_"));
        if cache_path.exists() {
            debug!("Cache hit for CID: {}", cid);
            return Ok(fs::read(&cache_path).await?);
        }

        // Try local IPFS first if available
        if self.local_available {
            info!("Fetching from local IPFS: {}", cid);
            use futures::TryStreamExt;

            match self.client
                .cat(cid)
                .map_ok(|chunk| chunk.to_vec())
                .try_concat()
                .await
            {
                Ok(data) => {
                    // Cache the result
                    fs::write(&cache_path, &data).await?;
                    debug!("Cached CID: {}", cid);
                    return Ok(data);
                }
                Err(e) => {
                    warn!("Local IPFS fetch failed: {}, trying public gateways...", e);
                }
            }
        }

        // Fallback to public gateways
        self.fetch_from_gateways(cid).await
    }

    /// Fetch from public IPFS gateways
    async fn fetch_from_gateways(&self, cid: &str) -> Result<Vec<u8>> {
        let cache_path = self.cache_dir.join(cid.replace("/", "_").replace(":", "_"));

        for gateway in PUBLIC_GATEWAYS {
            let url = format!("{}{}", gateway, cid);
            info!("Trying gateway: {}", url);

            match self.http_client.get(&url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.bytes().await {
                            Ok(bytes) => {
                                let data = bytes.to_vec();
                                info!("Successfully fetched {} bytes from {}", data.len(), gateway);

                                // Cache the result
                                if let Err(e) = fs::write(&cache_path, &data).await {
                                    warn!("Failed to cache: {}", e);
                                }

                                return Ok(data);
                            }
                            Err(e) => {
                                warn!("Failed to read response from {}: {}", gateway, e);
                            }
                        }
                    } else {
                        debug!("Gateway {} returned status: {}", gateway, response.status());
                    }
                }
                Err(e) => {
                    debug!("Gateway {} failed: {}", gateway, e);
                }
            }
        }

        anyhow::bail!("Failed to fetch CID {} from all gateways", cid)
    }

    /// Get file from IPFS by bytes32 hash (hex encoded)
    pub async fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        let hex_hash = format!("0x{}", hex::encode(hash));
        info!("Fetching from IPFS: {}", hex_hash);

        // For IPFS, the hash would typically be a CID
        // For testnet, we'll use the hex hash as a placeholder CID
        self.get_by_cid(&hex_hash).await
    }

    /// Add file to IPFS
    pub async fn add(&self, data: Vec<u8>) -> Result<String> {
        use std::io::Cursor;

        let cursor = Cursor::new(data);
        let response = self.client.add(cursor).await?;

        info!("Added to IPFS: {}", response.hash);
        Ok(response.hash)
    }

    /// Put data to IPFS (alias for add)
    pub async fn put(&self, data: &[u8]) -> Result<String> {
        self.add(data.to_vec()).await
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

    fn test_storage(cache_dir: PathBuf) -> IpfsStorage {
        IpfsStorage {
            client: IpfsClient::from_str("http://127.0.0.1:5001").unwrap(),
            http_client: HttpClient::new(),
            cache_dir,
            max_cache_mb: 100,
            local_available: false,
        }
    }

    #[tokio::test]
    async fn test_exists_with_cached_file() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();

        // Create a fake cached file
        let cid = "QmTestCid123";
        let cache_path = cache_dir.join(cid);
        fs::create_dir_all(&cache_dir).await.unwrap();
        fs::write(&cache_path, b"test content").await.unwrap();

        let storage = test_storage(cache_dir);

        assert!(storage.exists(cid).await);
        assert!(!storage.exists("QmNonExistent").await);
    }

    #[tokio::test]
    async fn test_cache_size_empty() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        fs::create_dir_all(&cache_dir).await.unwrap();

        let storage = test_storage(cache_dir);

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

        let storage = test_storage(cache_dir);

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

        let storage = test_storage(cache_dir);

        // Should succeed without error
        let result = storage.clean_cache().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipfs_storage_fields() {
        let storage = test_storage(PathBuf::from("/tmp/test"));

        assert_eq!(storage.cache_dir, PathBuf::from("/tmp/test"));
        assert_eq!(storage.max_cache_mb, 100);
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

        let storage = test_storage(cache_dir);

        // Getting from cache should work even without IPFS
        let result = storage.get_by_cid(cid).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), content.to_vec());
    }
}
