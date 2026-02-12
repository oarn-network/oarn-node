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
