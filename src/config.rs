//! Configuration management for OARN node
//!
//! IMPORTANT: No hardcoded values! All infrastructure is discovered dynamically.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Node operational mode
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NodeMode {
    /// Fully offline, local inference only
    Local,
    /// Standard P2P network mode
    #[default]
    Standard,
    /// High-speed validator-routed mode
    ValidatorRouted,
    /// Automatic mode selection based on connectivity
    Auto,
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to this config file
    #[serde(skip)]
    pub path: PathBuf,

    /// Node operational mode
    #[serde(default)]
    pub mode: NodeMode,

    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Blockchain configuration
    #[serde(default)]
    pub blockchain: BlockchainConfig,

    /// Storage configuration
    #[serde(default)]
    pub storage: StorageConfig,

    /// Compute configuration
    #[serde(default)]
    pub compute: ComputeConfig,

    /// Privacy configuration
    #[serde(default)]
    pub privacy: PrivacyConfig,

    /// Wallet configuration
    #[serde(default)]
    pub wallet: WalletConfig,
}

/// Network/P2P configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Addresses to listen on
    #[serde(default = "default_listen_addresses")]
    pub listen_addresses: Vec<String>,

    /// Discovery method (NEVER hardcode bootstrap nodes!)
    #[serde(default)]
    pub discovery: DiscoveryConfig,

    /// Maximum number of peers
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,

    /// Connection timeout in seconds
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addresses: default_listen_addresses(),
            discovery: DiscoveryConfig::default(),
            max_peers: default_max_peers(),
            connection_timeout: default_connection_timeout(),
        }
    }
}

/// Discovery configuration - NO HARDCODED VALUES
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery method: "auto", "dht", "ens", "manual"
    #[serde(default = "default_discovery_method")]
    pub method: String,

    /// ENS name for registry discovery
    #[serde(default = "default_ens_registry")]
    pub ens_registry: String,

    /// DHT protocol name
    #[serde(default = "default_dht_protocol")]
    pub dht_protocol: String,

    /// Manual bootstrap nodes (only if method = "manual", for testing)
    #[serde(default)]
    pub manual_bootstrap: Vec<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            method: default_discovery_method(),
            ens_registry: default_ens_registry(),
            dht_protocol: default_dht_protocol(),
            manual_bootstrap: vec![],
        }
    }
}

/// Blockchain configuration - NO HARDCODED RPC URLS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    /// Chain ID (421614 = Arbitrum Sepolia, 42161 = Arbitrum One)
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,

    /// RPC discovery method: "registry", "ens", "manual"
    #[serde(default = "default_rpc_discovery")]
    pub rpc_discovery: String,

    /// Manual RPC URL (only for testing, prefer discovery)
    pub manual_rpc_url: Option<String>,

    /// Number of RPC providers to use for redundancy
    #[serde(default = "default_rpc_redundancy")]
    pub rpc_redundancy: usize,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            chain_id: default_chain_id(),
            rpc_discovery: default_rpc_discovery(),
            manual_rpc_url: None,
            rpc_redundancy: default_rpc_redundancy(),
        }
    }
}

/// Storage/IPFS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Local IPFS API endpoint
    #[serde(default = "default_ipfs_api")]
    pub ipfs_api: String,

    /// Local cache directory
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,

    /// Maximum cache size in MB
    #[serde(default = "default_cache_size")]
    pub max_cache_mb: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            ipfs_api: default_ipfs_api(),
            cache_dir: default_cache_dir(),
            max_cache_mb: default_cache_size(),
        }
    }
}

/// Compute/inference configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeConfig {
    /// Maximum VRAM to use (in MB)
    #[serde(default)]
    pub max_vram_mb: Option<u64>,

    /// Maximum RAM to use (in MB)
    #[serde(default)]
    pub max_ram_mb: Option<u64>,

    /// Supported frameworks
    #[serde(default = "default_frameworks")]
    pub frameworks: Vec<String>,

    /// Number of concurrent tasks
    #[serde(default = "default_concurrent_tasks")]
    pub concurrent_tasks: usize,
}

impl Default for ComputeConfig {
    fn default() -> Self {
        Self {
            max_vram_mb: None,
            max_ram_mb: None,
            frameworks: default_frameworks(),
            concurrent_tasks: default_concurrent_tasks(),
        }
    }
}

/// Privacy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Enable Tor for all connections
    #[serde(default)]
    pub tor_enabled: bool,

    /// Enable message padding (traffic analysis resistance)
    #[serde(default = "default_true")]
    pub padding_enabled: bool,

    /// Rotate peer connections periodically
    #[serde(default = "default_true")]
    pub rotate_peers: bool,

    /// Peer rotation interval in minutes
    #[serde(default = "default_rotation_interval")]
    pub rotation_interval_mins: u64,

    /// Use ephemeral wallet addresses per task
    #[serde(default)]
    pub ephemeral_addresses: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            tor_enabled: false,
            padding_enabled: true,
            rotate_peers: true,
            rotation_interval_mins: default_rotation_interval(),
            ephemeral_addresses: false,
        }
    }
}

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Path to encrypted keystore file
    pub keystore_path: Option<PathBuf>,

    /// Use HD wallet derivation
    #[serde(default = "default_true")]
    pub use_hd_wallet: bool,

    /// HD derivation path
    #[serde(default = "default_derivation_path")]
    pub derivation_path: String,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            keystore_path: None,
            use_hd_wallet: true,
            derivation_path: default_derivation_path(),
        }
    }
}

// Default value functions
fn default_listen_addresses() -> Vec<String> {
    vec![
        "/ip4/0.0.0.0/tcp/4001".to_string(),
        "/ip6/::/tcp/4001".to_string(),
    ]
}

fn default_max_peers() -> usize { 50 }
fn default_connection_timeout() -> u64 { 30 }
fn default_discovery_method() -> String { "auto".to_string() }
fn default_ens_registry() -> String { "oarn-registry.eth".to_string() }
fn default_dht_protocol() -> String { "/oarn/kad/1.0.0".to_string() }
fn default_chain_id() -> u64 { 421614 } // Arbitrum Sepolia
fn default_rpc_discovery() -> String { "registry".to_string() }
fn default_rpc_redundancy() -> usize { 3 }
fn default_ipfs_api() -> String { "http://127.0.0.1:5001".to_string() }
fn default_cache_dir() -> PathBuf {
    dirs::cache_dir().unwrap_or_else(|| PathBuf::from(".")).join("oarn")
}
fn default_cache_size() -> u64 { 10240 } // 10 GB
fn default_frameworks() -> Vec<String> { vec!["onnx".to_string(), "pytorch".to_string()] }
fn default_concurrent_tasks() -> usize { 1 }
fn default_true() -> bool { true }
fn default_rotation_interval() -> u64 { 30 }
fn default_derivation_path() -> String { "m/44'/60'/0'/0".to_string() }

impl Config {
    /// Load configuration from file
    pub fn load(path: &Path) -> Result<Self> {
        let expanded_path = shellexpand::tilde(&path.to_string_lossy()).to_string();
        let path = PathBuf::from(expanded_path);

        if !path.exists() {
            tracing::warn!("Config file not found, using defaults");
            return Ok(Self::default_with_path(path));
        }

        let content = std::fs::read_to_string(&path)
            .context("Failed to read config file")?;

        let mut config: Config = toml::from_str(&content)
            .context("Failed to parse config file")?;

        config.path = path;
        Ok(config)
    }

    /// Create default configuration file
    pub fn create_default() -> Result<PathBuf> {
        let config_dir = dirs::home_dir()
            .context("Could not find home directory")?
            .join(".oarn");

        std::fs::create_dir_all(&config_dir)?;

        let config_path = config_dir.join("config.toml");
        let config = Self::default_with_path(config_path.clone());

        let content = toml::to_string_pretty(&config)?;
        std::fs::write(&config_path, content)?;

        Ok(config_path)
    }

    fn default_with_path(path: PathBuf) -> Self {
        Self {
            path,
            mode: NodeMode::default(),
            network: NetworkConfig::default(),
            blockchain: BlockchainConfig::default(),
            storage: StorageConfig::default(),
            compute: ComputeConfig::default(),
            privacy: PrivacyConfig::default(),
            wallet: WalletConfig::default(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::default_with_path(PathBuf::from("~/.oarn/config.toml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_node_mode_default() {
        let mode = NodeMode::default();
        assert!(matches!(mode, NodeMode::Standard));
    }

    #[test]
    fn test_node_mode_serialization() {
        let mode = NodeMode::ValidatorRouted;
        let serialized = toml::to_string(&mode).unwrap();
        assert!(serialized.contains("validatorrouted"));
    }

    #[test]
    fn test_network_config_defaults() {
        let config = NetworkConfig::default();
        assert_eq!(config.max_peers, 50);
        assert_eq!(config.connection_timeout, 30);
        assert!(config.listen_addresses.len() == 2);
    }

    #[test]
    fn test_discovery_config_defaults() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.method, "auto");
        assert_eq!(config.ens_registry, "oarn-registry.eth");
        assert_eq!(config.dht_protocol, "/oarn/kad/1.0.0");
        assert!(config.manual_bootstrap.is_empty());
    }

    #[test]
    fn test_blockchain_config_defaults() {
        let config = BlockchainConfig::default();
        assert_eq!(config.chain_id, 421614); // Arbitrum Sepolia
        assert_eq!(config.rpc_discovery, "registry");
        assert_eq!(config.rpc_redundancy, 3);
        assert!(config.manual_rpc_url.is_none());
    }

    #[test]
    fn test_storage_config_defaults() {
        let config = StorageConfig::default();
        assert_eq!(config.ipfs_api, "http://127.0.0.1:5001");
        assert_eq!(config.max_cache_mb, 10240);
    }

    #[test]
    fn test_compute_config_defaults() {
        let config = ComputeConfig::default();
        assert!(config.max_vram_mb.is_none());
        assert!(config.max_ram_mb.is_none());
        assert_eq!(config.concurrent_tasks, 1);
        assert!(config.frameworks.contains(&"onnx".to_string()));
    }

    #[test]
    fn test_privacy_config_defaults() {
        let config = PrivacyConfig::default();
        assert!(!config.tor_enabled);
        assert!(config.padding_enabled);
        assert!(config.rotate_peers);
        assert_eq!(config.rotation_interval_mins, 30);
        assert!(!config.ephemeral_addresses);
    }

    #[test]
    fn test_wallet_config_defaults() {
        let config = WalletConfig::default();
        assert!(config.keystore_path.is_none());
        assert!(config.use_hd_wallet);
        assert_eq!(config.derivation_path, "m/44'/60'/0'/0");
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(matches!(config.mode, NodeMode::Standard));
        assert_eq!(config.blockchain.chain_id, 421614);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = Config::load(Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_ok());
        // Should return default config when file doesn't exist
        let config = result.unwrap();
        assert!(matches!(config.mode, NodeMode::Standard));
    }

    #[test]
    fn test_load_valid_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        let content = r#"
mode = "local"

[network]
max_peers = 100

[blockchain]
chain_id = 42161
"#;
        fs::write(&config_path, content).unwrap();

        let config = Config::load(&config_path).unwrap();
        assert!(matches!(config.mode, NodeMode::Local));
        assert_eq!(config.network.max_peers, 100);
        assert_eq!(config.blockchain.chain_id, 42161);
    }

    #[test]
    fn test_load_partial_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        // Only specify some fields, rest should use defaults
        let content = r#"
mode = "validatorrouted"
"#;
        fs::write(&config_path, content).unwrap();

        let config = Config::load(&config_path).unwrap();
        assert!(matches!(config.mode, NodeMode::ValidatorRouted));
        // Defaults should be applied
        assert_eq!(config.network.max_peers, 50);
        assert_eq!(config.blockchain.chain_id, 421614);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = Config::default();
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();

        assert_eq!(config.network.max_peers, deserialized.network.max_peers);
        assert_eq!(config.blockchain.chain_id, deserialized.blockchain.chain_id);
    }

    #[test]
    fn test_default_listen_addresses() {
        let addresses = default_listen_addresses();
        assert_eq!(addresses.len(), 2);
        assert!(addresses[0].contains("/ip4/0.0.0.0"));
        assert!(addresses[1].contains("/ip6/::"));
    }

    #[test]
    fn test_default_cache_dir() {
        let cache_dir = default_cache_dir();
        assert!(cache_dir.to_string_lossy().contains("oarn"));
    }
}
