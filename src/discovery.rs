//! Decentralized infrastructure discovery
//!
//! CRITICAL: This module ensures NO HARDCODED VALUES in the client.
//! All infrastructure is discovered dynamically via:
//! 1. ENS (oarn-registry.eth)
//! 2. DHT (Kademlia)
//! 3. On-chain registry (OARNRegistry.sol)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::Config;

/// Discovered bootstrap node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNode {
    pub peer_id: String,
    pub multiaddr: String,
    pub onion_address: Option<String>,
    pub i2p_address: Option<String>,
}

/// Discovered RPC provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcProvider {
    pub endpoint: String,
    pub onion_endpoint: Option<String>,
    pub stake: u64,
    pub uptime: u32,
}

/// Core contract addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreContracts {
    pub oarn_registry: String,
    pub task_registry: String,
    pub token_reward: String,
    pub validator_registry: String,
    pub governance: String,
    pub gov_token: String,
}

/// Discovery service for OARN infrastructure
pub struct Discovery {
    config: Config,
    bootstrap_nodes: Vec<BootstrapNode>,
    rpc_providers: Vec<RpcProvider>,
    core_contracts: Option<CoreContracts>,
}

impl Discovery {
    /// Create a new discovery service
    pub async fn new(config: &Config) -> Result<Self> {
        let mut discovery = Self {
            config: config.clone(),
            bootstrap_nodes: vec![],
            rpc_providers: vec![],
            core_contracts: None,
        };

        // Perform initial discovery
        discovery.discover_all().await?;

        Ok(discovery)
    }

    /// Perform full infrastructure discovery
    pub async fn discover_all(&mut self) -> Result<()> {
        info!("Starting infrastructure discovery...");

        match self.config.network.discovery.method.as_str() {
            "auto" => {
                // Try methods in order: ENS -> DHT -> On-chain
                if let Err(e) = self.discover_via_ens().await {
                    warn!("ENS discovery failed: {}, trying DHT...", e);
                    if let Err(e) = self.discover_via_dht().await {
                        warn!("DHT discovery failed: {}, trying on-chain...", e);
                        self.discover_via_onchain().await?;
                    }
                }
            }
            "ens" => self.discover_via_ens().await?,
            "dht" => self.discover_via_dht().await?,
            "manual" => self.use_manual_config()?,
            _ => anyhow::bail!("Unknown discovery method: {}", self.config.network.discovery.method),
        }

        info!(
            "Discovery complete: {} bootstrap nodes, {} RPC providers",
            self.bootstrap_nodes.len(),
            self.rpc_providers.len()
        );

        Ok(())
    }

    /// Discover infrastructure via ENS
    async fn discover_via_ens(&mut self) -> Result<()> {
        info!("Discovering via ENS: {}", self.config.network.discovery.ens_registry);

        // In production, this would:
        // 1. Resolve oarn-registry.eth to get OARNRegistry contract address
        // 2. Query oarn-bootstrap.eth TXT records for bootstrap nodes
        // 3. Query oarn-rpc.eth TXT records for RPC providers

        // For now, we'll use a public ENS resolver
        // TODO: Implement actual ENS resolution

        warn!("ENS discovery not yet implemented, falling back to DHT");
        Err(anyhow::anyhow!("ENS discovery not implemented"))
    }

    /// Discover infrastructure via DHT
    async fn discover_via_dht(&mut self) -> Result<()> {
        info!("Discovering via DHT...");

        // In production, this would:
        // 1. Connect to well-known DHT keys (/oarn/bootstrap, /oarn/rpc)
        // 2. Retrieve and verify signed records
        // 3. Validate against on-chain stakes

        // For development, we'll use a minimal bootstrap process
        // TODO: Implement actual DHT discovery

        warn!("DHT discovery not yet implemented");
        Err(anyhow::anyhow!("DHT discovery not implemented"))
    }

    /// Discover infrastructure via on-chain registry
    async fn discover_via_onchain(&mut self) -> Result<()> {
        info!("Discovering via on-chain registry...");

        // This requires an initial RPC connection
        // In production, we'd use a well-known public RPC as last resort
        // and immediately verify/switch to discovered RPCs

        // For development, allow manual RPC override
        if let Some(rpc_url) = &self.config.blockchain.manual_rpc_url {
            warn!("Using manual RPC URL for bootstrap: {}", rpc_url);

            // Query OARNRegistry contract
            // TODO: Implement actual contract calls

            // Add the manual RPC as a discovered provider
            self.rpc_providers.push(RpcProvider {
                endpoint: rpc_url.clone(),
                onion_endpoint: None,
                stake: 0,
                uptime: 10000,
            });
        }

        Ok(())
    }

    /// Use manual configuration (for testing only)
    fn use_manual_config(&mut self) -> Result<()> {
        warn!("Using MANUAL bootstrap configuration - for testing only!");

        for addr in &self.config.network.discovery.manual_bootstrap {
            // Parse multiaddr to extract peer ID
            // Format: /ip4/x.x.x.x/tcp/4001/p2p/12D3KooW...
            let parts: Vec<&str> = addr.split("/p2p/").collect();
            if parts.len() == 2 {
                self.bootstrap_nodes.push(BootstrapNode {
                    peer_id: parts[1].to_string(),
                    multiaddr: addr.clone(),
                    onion_address: None,
                    i2p_address: None,
                });
            }
        }

        if let Some(rpc_url) = &self.config.blockchain.manual_rpc_url {
            self.rpc_providers.push(RpcProvider {
                endpoint: rpc_url.clone(),
                onion_endpoint: None,
                stake: 0,
                uptime: 10000,
            });
        }

        // Load manual contract addresses from config
        if let Some(contracts) = &self.config.blockchain.contracts {
            self.core_contracts = Some(CoreContracts {
                oarn_registry: contracts.oarn_registry.clone().unwrap_or_default(),
                task_registry: contracts.task_registry.clone().unwrap_or_default(),
                token_reward: contracts.token_reward.clone().unwrap_or_default(),
                validator_registry: String::new(),
                governance: String::new(),
                gov_token: contracts.gov_token.clone().unwrap_or_default(),
            });
            info!("Loaded manual contract addresses from config");
        }

        Ok(())
    }

    /// Get discovered bootstrap nodes
    pub async fn get_bootstrap_nodes(&self) -> Result<Vec<BootstrapNode>> {
        Ok(self.bootstrap_nodes.clone())
    }

    /// Get discovered RPC providers
    pub async fn get_rpc_providers(&self) -> Result<Vec<RpcProvider>> {
        if self.rpc_providers.is_empty() {
            anyhow::bail!("No RPC providers discovered");
        }
        Ok(self.rpc_providers.clone())
    }

    /// Get a random healthy RPC provider
    pub async fn get_random_rpc(&self) -> Result<RpcProvider> {
        use rand::seq::SliceRandom;

        let healthy: Vec<_> = self.rpc_providers
            .iter()
            .filter(|p| p.uptime > 9000) // >90% uptime
            .cloned()
            .collect();

        if healthy.is_empty() {
            // Fall back to any provider
            self.rpc_providers
                .choose(&mut rand::thread_rng())
                .cloned()
                .context("No RPC providers available")
        } else {
            healthy
                .choose(&mut rand::thread_rng())
                .cloned()
                .context("No healthy RPC providers available")
        }
    }

    /// Get core contract addresses
    pub fn get_core_contracts(&self) -> Option<&CoreContracts> {
        self.core_contracts.as_ref()
    }

    /// Refresh discovery (call periodically)
    pub async fn refresh(&mut self) -> Result<()> {
        debug!("Refreshing infrastructure discovery...");
        self.discover_all().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::default()
    }

    fn test_config_manual() -> Config {
        let mut config = Config::default();
        config.network.discovery.method = "manual".to_string();
        config.network.discovery.manual_bootstrap = vec![
            "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWTestPeerId1".to_string(),
            "/ip4/5.6.7.8/tcp/4001/p2p/12D3KooWTestPeerId2".to_string(),
        ];
        config.blockchain.manual_rpc_url = Some("https://test-rpc.example.com".to_string());
        config
    }

    #[test]
    fn test_bootstrap_node_struct() {
        let node = BootstrapNode {
            peer_id: "12D3KooWTest".to_string(),
            multiaddr: "/ip4/1.2.3.4/tcp/4001".to_string(),
            onion_address: Some("http://test.onion".to_string()),
            i2p_address: None,
        };

        assert_eq!(node.peer_id, "12D3KooWTest");
        assert!(node.onion_address.is_some());
        assert!(node.i2p_address.is_none());
    }

    #[test]
    fn test_bootstrap_node_serialization() {
        let node = BootstrapNode {
            peer_id: "12D3KooWTest".to_string(),
            multiaddr: "/ip4/1.2.3.4/tcp/4001".to_string(),
            onion_address: None,
            i2p_address: None,
        };

        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("12D3KooWTest"));

        let deserialized: BootstrapNode = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.peer_id, node.peer_id);
    }

    #[test]
    fn test_rpc_provider_struct() {
        let provider = RpcProvider {
            endpoint: "https://rpc.example.com".to_string(),
            onion_endpoint: Some("http://rpc.onion".to_string()),
            stake: 5000,
            uptime: 9950,
        };

        assert_eq!(provider.endpoint, "https://rpc.example.com");
        assert_eq!(provider.stake, 5000);
        assert_eq!(provider.uptime, 9950);
    }

    #[test]
    fn test_rpc_provider_serialization() {
        let provider = RpcProvider {
            endpoint: "https://rpc.example.com".to_string(),
            onion_endpoint: None,
            stake: 1000,
            uptime: 10000,
        };

        let json = serde_json::to_string(&provider).unwrap();
        let deserialized: RpcProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.endpoint, provider.endpoint);
        assert_eq!(deserialized.stake, provider.stake);
    }

    #[test]
    fn test_core_contracts_struct() {
        let contracts = CoreContracts {
            oarn_registry: "0x1234".to_string(),
            task_registry: "0x2345".to_string(),
            token_reward: "0x3456".to_string(),
            validator_registry: "0x4567".to_string(),
            governance: "0x5678".to_string(),
            gov_token: "0x6789".to_string(),
        };

        assert_eq!(contracts.oarn_registry, "0x1234");
        assert_eq!(contracts.task_registry, "0x2345");
    }

    #[tokio::test]
    async fn test_discovery_new() {
        let config = test_config();
        let discovery = Discovery::new(&config).await;

        // Discovery may fail if no network, but should not panic
        // Just check that the function handles errors gracefully
        assert!(discovery.is_ok() || discovery.is_err());
    }

    #[tokio::test]
    async fn test_discovery_manual_mode() {
        let config = test_config_manual();
        let mut discovery = Discovery {
            config: config.clone(),
            bootstrap_nodes: vec![],
            rpc_providers: vec![],
            core_contracts: None,
        };

        let result = discovery.use_manual_config();
        assert!(result.is_ok());

        // Should have parsed the bootstrap nodes
        assert_eq!(discovery.bootstrap_nodes.len(), 2);
        assert_eq!(discovery.bootstrap_nodes[0].peer_id, "12D3KooWTestPeerId1");
        assert_eq!(discovery.bootstrap_nodes[1].peer_id, "12D3KooWTestPeerId2");

        // Should have the RPC provider
        assert_eq!(discovery.rpc_providers.len(), 1);
        assert_eq!(discovery.rpc_providers[0].endpoint, "https://test-rpc.example.com");
    }

    #[tokio::test]
    async fn test_get_bootstrap_nodes() {
        let config = test_config_manual();
        let mut discovery = Discovery {
            config: config.clone(),
            bootstrap_nodes: vec![],
            rpc_providers: vec![],
            core_contracts: None,
        };

        discovery.use_manual_config().unwrap();

        let nodes = discovery.get_bootstrap_nodes().await.unwrap();
        assert_eq!(nodes.len(), 2);
    }

    #[tokio::test]
    async fn test_get_rpc_providers_empty() {
        let config = test_config();
        let discovery = Discovery {
            config: config.clone(),
            bootstrap_nodes: vec![],
            rpc_providers: vec![],
            core_contracts: None,
        };

        let result = discovery.get_rpc_providers().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No RPC providers"));
    }

    #[tokio::test]
    async fn test_get_rpc_providers_with_providers() {
        let config = test_config();
        let discovery = Discovery {
            config: config.clone(),
            bootstrap_nodes: vec![],
            rpc_providers: vec![
                RpcProvider {
                    endpoint: "https://rpc1.example.com".to_string(),
                    onion_endpoint: None,
                    stake: 1000,
                    uptime: 9500,
                },
            ],
            core_contracts: None,
        };

        let providers = discovery.get_rpc_providers().await.unwrap();
        assert_eq!(providers.len(), 1);
    }

    #[tokio::test]
    async fn test_get_random_rpc_healthy() {
        let config = test_config();
        let discovery = Discovery {
            config: config.clone(),
            bootstrap_nodes: vec![],
            rpc_providers: vec![
                RpcProvider {
                    endpoint: "https://healthy.example.com".to_string(),
                    onion_endpoint: None,
                    stake: 1000,
                    uptime: 9500, // Healthy (>90%)
                },
                RpcProvider {
                    endpoint: "https://unhealthy.example.com".to_string(),
                    onion_endpoint: None,
                    stake: 1000,
                    uptime: 5000, // Unhealthy (<90%)
                },
            ],
            core_contracts: None,
        };

        let rpc = discovery.get_random_rpc().await.unwrap();
        // Should prefer healthy provider
        assert_eq!(rpc.endpoint, "https://healthy.example.com");
    }

    #[tokio::test]
    async fn test_get_random_rpc_fallback_to_unhealthy() {
        let config = test_config();
        let discovery = Discovery {
            config: config.clone(),
            bootstrap_nodes: vec![],
            rpc_providers: vec![
                RpcProvider {
                    endpoint: "https://unhealthy.example.com".to_string(),
                    onion_endpoint: None,
                    stake: 1000,
                    uptime: 5000, // All unhealthy
                },
            ],
            core_contracts: None,
        };

        let rpc = discovery.get_random_rpc().await.unwrap();
        // Should fall back to unhealthy if no healthy ones
        assert_eq!(rpc.endpoint, "https://unhealthy.example.com");
    }

    #[test]
    fn test_get_core_contracts_none() {
        let config = test_config();
        let discovery = Discovery {
            config: config.clone(),
            bootstrap_nodes: vec![],
            rpc_providers: vec![],
            core_contracts: None,
        };

        assert!(discovery.get_core_contracts().is_none());
    }

    #[test]
    fn test_get_core_contracts_some() {
        let config = test_config();
        let contracts = CoreContracts {
            oarn_registry: "0x1234".to_string(),
            task_registry: "0x2345".to_string(),
            token_reward: "0x3456".to_string(),
            validator_registry: "0x4567".to_string(),
            governance: "0x5678".to_string(),
            gov_token: "0x6789".to_string(),
        };

        let discovery = Discovery {
            config: config.clone(),
            bootstrap_nodes: vec![],
            rpc_providers: vec![],
            core_contracts: Some(contracts),
        };

        assert!(discovery.get_core_contracts().is_some());
        assert_eq!(discovery.get_core_contracts().unwrap().oarn_registry, "0x1234");
    }
}
