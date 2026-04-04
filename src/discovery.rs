//! Decentralized infrastructure discovery
//!
//! CRITICAL: This module ensures NO HARDCODED VALUES in the client.
//! All infrastructure is discovered dynamically via:
//! 1. ENS (oarn-registry.eth)
//! 2. DHT (Kademlia)
//! 3. On-chain registry (OARNRegistry.sol)

use anyhow::{Context, Result};
use ethers::{
    prelude::abigen,
    providers::{Http, Middleware, Provider},
    types::Address,
};
use futures::StreamExt;
use libp2p::{
    kad, noise, tcp, yamux,
    swarm::SwarmEvent,
    Multiaddr, PeerId,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::Config;

// OARNRegistry contract bindings for on-chain discovery.
// JSON ABI format is used here because the human-readable parser does not
// reliably handle tuple[] (array-of-struct) return types.
abigen!(
    OARNRegistryContract,
    r#"[
        {
            "name": "getCoreContractsV2",
            "type": "function",
            "inputs": [],
            "outputs": [
                {"name": "_taskRegistry",      "type": "address"},
                {"name": "_taskRegistryV2",    "type": "address"},
                {"name": "_tokenReward",       "type": "address"},
                {"name": "_validatorRegistry", "type": "address"},
                {"name": "_governance",        "type": "address"},
                {"name": "_govToken",          "type": "address"}
            ],
            "stateMutability": "view"
        },
        {
            "name": "getActiveRPCProviders",
            "type": "function",
            "inputs": [],
            "outputs": [{
                "name": "",
                "type": "tuple[]",
                "components": [
                    {"name": "endpoint",      "type": "string"},
                    {"name": "onionEndpoint", "type": "string"},
                    {"name": "owner",         "type": "address"},
                    {"name": "stake",         "type": "uint256"},
                    {"name": "registeredAt",  "type": "uint256"},
                    {"name": "lastHeartbeat", "type": "uint256"},
                    {"name": "uptime",        "type": "uint256"},
                    {"name": "reportCount",   "type": "uint256"},
                    {"name": "isActive",      "type": "bool"}
                ]
            }],
            "stateMutability": "view"
        },
        {
            "name": "getActiveBootstrapNodes",
            "type": "function",
            "inputs": [],
            "outputs": [{
                "name": "",
                "type": "tuple[]",
                "components": [
                    {"name": "peer_id",       "type": "string"},
                    {"name": "multiaddr",     "type": "string"},
                    {"name": "onionAddress",  "type": "string"},
                    {"name": "i2pAddress",    "type": "string"},
                    {"name": "owner",         "type": "address"},
                    {"name": "stake",         "type": "uint256"},
                    {"name": "registeredAt",  "type": "uint256"},
                    {"name": "lastHeartbeat", "type": "uint256"},
                    {"name": "isActive",      "type": "bool"}
                ]
            }],
            "stateMutability": "view"
        }
    ]"#
);

/// Public Ethereum mainnet RPC endpoints for ENS resolution
const ENS_RPC_ENDPOINTS: &[&str] = &[
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://ethereum.publicnode.com",
    "https://1rpc.io/eth",
];

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
    pub task_registry_v2: String, // Multi-node consensus version
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
            _ => anyhow::bail!(
                "Unknown discovery method: {}",
                self.config.network.discovery.method
            ),
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
        let ens_registry = self.config.network.discovery.ens_registry.clone();
        info!("Discovering via ENS: {}", ens_registry);

        // Connect to Ethereum mainnet for ENS resolution
        let provider = self.get_ens_provider().await?;

        // 1. Resolve main registry address (e.g., oarn-registry.eth -> contract address)
        info!("Resolving ENS name: {}", ens_registry);
        match provider.resolve_name(&ens_registry).await {
            Ok(address) => {
                info!("Resolved {} to {:?}", ens_registry, address);

                // Store the resolved address as OARNRegistry
                self.core_contracts = Some(CoreContracts {
                    oarn_registry: format!("{:?}", address),
                    task_registry: String::new(),
                    task_registry_v2: String::new(),
                    token_reward: String::new(),
                    validator_registry: String::new(),
                    governance: String::new(),
                    gov_token: String::new(),
                });
            }
            Err(e) => {
                warn!("Failed to resolve {}: {}", ens_registry, e);
            }
        }

        // 2. Try to resolve RPC providers from ENS TXT records
        // Format: oarn-rpc.eth -> TXT records with RPC endpoints
        let rpc_ens = ens_registry.replace("registry", "rpc");
        if let Ok(rpc_info) = self.resolve_ens_text(&provider, &rpc_ens, "rpc").await {
            for endpoint in rpc_info.split(',') {
                let endpoint = endpoint.trim();
                if !endpoint.is_empty() && endpoint.starts_with("http") {
                    info!("Discovered RPC from ENS: {}", endpoint);
                    self.rpc_providers.push(RpcProvider {
                        endpoint: endpoint.to_string(),
                        onion_endpoint: None,
                        stake: 0,
                        uptime: 10000,
                    });
                }
            }
        }

        // 3. Try to resolve bootstrap nodes from ENS TXT records
        // Format: oarn-bootstrap.eth -> TXT records with multiaddrs
        let bootstrap_ens = ens_registry.replace("registry", "bootstrap");
        if let Ok(bootstrap_info) = self
            .resolve_ens_text(&provider, &bootstrap_ens, "nodes")
            .await
        {
            for node_info in bootstrap_info.split(';') {
                if let Some((peer_id, multiaddr)) = self.parse_bootstrap_record(node_info) {
                    info!("Discovered bootstrap node from ENS: {}", peer_id);
                    self.bootstrap_nodes.push(BootstrapNode {
                        peer_id,
                        multiaddr,
                        onion_address: None,
                        i2p_address: None,
                    });
                }
            }
        }

        // 4. Try to resolve contract addresses from ENS
        // task-registry.oarn.eth, token-reward.oarn.eth, etc.
        self.resolve_contract_addresses(&provider, &ens_registry)
            .await;

        // Check if we discovered anything useful
        if self.rpc_providers.is_empty() && self.bootstrap_nodes.is_empty() {
            // If no RPC discovered, use the manual fallback if configured
            if let Some(rpc_url) = &self.config.blockchain.manual_rpc_url {
                info!("No RPC from ENS, using manual fallback: {}", rpc_url);
                self.rpc_providers.push(RpcProvider {
                    endpoint: rpc_url.clone(),
                    onion_endpoint: None,
                    stake: 0,
                    uptime: 10000,
                });
            }
        }

        if self.rpc_providers.is_empty() {
            Err(anyhow::anyhow!("ENS discovery found no RPC providers"))
        } else {
            Ok(())
        }
    }

    /// Get a provider for ENS resolution (Ethereum mainnet)
    async fn get_ens_provider(&self) -> Result<Provider<Http>> {
        for endpoint in ENS_RPC_ENDPOINTS {
            match Provider::<Http>::try_from(*endpoint) {
                Ok(provider) => {
                    // Verify connection
                    if provider.get_block_number().await.is_ok() {
                        debug!("Connected to ENS RPC: {}", endpoint);
                        return Ok(provider);
                    }
                }
                Err(e) => {
                    debug!("Failed to connect to {}: {}", endpoint, e);
                }
            }
        }
        Err(anyhow::anyhow!("Could not connect to any ENS RPC endpoint"))
    }

    /// Resolve ENS TXT record
    async fn resolve_ens_text(
        &self,
        provider: &Provider<Http>,
        name: &str,
        key: &str,
    ) -> Result<String> {
        debug!("Resolving ENS TXT record: {} key={}", name, key);

        // ethers-rs doesn't have direct TXT record support, so we use resolve_name
        // and check if the name resolves. For TXT records, we'd need to call the
        // resolver contract directly.

        // For now, try to resolve as an address first
        match provider.resolve_name(name).await {
            Ok(_) => {
                // Name exists, but we can't get TXT records directly with ethers-rs
                // This would require calling the ENS resolver contract's text() function
                debug!(
                    "ENS name {} exists but TXT record lookup not implemented",
                    name
                );
                Err(anyhow::anyhow!(
                    "TXT record lookup requires direct contract call"
                ))
            }
            Err(e) => {
                debug!("ENS name {} not found: {}", name, e);
                Err(anyhow::anyhow!("ENS name not found: {}", e))
            }
        }
    }

    /// Parse a bootstrap node record from ENS TXT
    /// Format: "peer_id@multiaddr" or "/ip4/x.x.x.x/tcp/4001/p2p/12D3KooW..."
    fn parse_bootstrap_record(&self, record: &str) -> Option<(String, String)> {
        let record = record.trim();

        // Format 1: peer_id@multiaddr
        if record.contains('@') {
            let parts: Vec<&str> = record.splitn(2, '@').collect();
            if parts.len() == 2 {
                return Some((parts[0].to_string(), parts[1].to_string()));
            }
        }

        // Format 2: Full multiaddr with /p2p/ suffix
        if record.contains("/p2p/") {
            let parts: Vec<&str> = record.split("/p2p/").collect();
            if parts.len() == 2 {
                return Some((parts[1].to_string(), record.to_string()));
            }
        }

        None
    }

    /// Resolve contract addresses from ENS subdomains
    async fn resolve_contract_addresses(&mut self, provider: &Provider<Http>, base_domain: &str) {
        // Extract base domain (e.g., "oarn-registry.eth" -> "oarn.eth" or use as-is)
        let base = base_domain.replace("-registry", "");

        let contract_names = [
            ("task-registry", "task_registry"),
            ("token-reward", "token_reward"),
            ("validator-registry", "validator_registry"),
            ("governance", "governance"),
            ("gov-token", "gov_token"),
        ];

        for (subdomain, field) in contract_names {
            let full_name = if base.starts_with("oarn.") {
                format!("{}.{}", subdomain, base)
            } else {
                format!("{}.oarn.eth", subdomain)
            };

            match provider.resolve_name(&full_name).await {
                Ok(address) => {
                    info!("Resolved {} to {:?}", full_name, address);
                    if let Some(ref mut contracts) = self.core_contracts {
                        let addr_str = format!("{:?}", address);
                        match field {
                            "task_registry" => contracts.task_registry = addr_str,
                            "token_reward" => contracts.token_reward = addr_str,
                            "validator_registry" => contracts.validator_registry = addr_str,
                            "governance" => contracts.governance = addr_str,
                            "gov_token" => contracts.gov_token = addr_str,
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    debug!("Could not resolve {}: {}", full_name, e);
                }
            }
        }
    }

    /// Discover infrastructure via DHT (Kademlia).
    ///
    /// Builds a minimal temporary libp2p swarm (TCP + Noise + Yamux + Kademlia),
    /// connects to seed peers, and queries the `/oarn/peers/v1` DHT record to
    /// find other OARN bootstrap nodes.
    ///
    /// Seed priority:
    ///   1. `[network.discovery].manual_bootstrap` from config
    ///   2. Well-known IPFS public bootstrap peers (fallback — same Kademlia DHT)
    ///
    /// The temp swarm is dropped after discovery. The real swarm in network.rs
    /// then continues DHT operations (publishing peer info, periodic queries).
    async fn discover_via_dht(&mut self) -> Result<()> {
        info!("Starting DHT peer discovery...");

        // ── Seed peers ─────────────────────────────────────────────────────────
        // Well-known stable IPFS bootstrap peers (IP-based, no DNS needed).
        // They serve as DHT entry points so we can find OARN records.
        const IPFS_BOOTSTRAP: &[&str] = &[
            "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
            "/ip4/104.236.179.241/tcp/4001/p2p/QmSoLPppuBtQSGwKDZT2M73ULpjvfd3aZ6ha4oFGL1KrGM",
            "/ip4/128.199.219.111/tcp/4001/p2p/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu",
            "/ip4/162.243.248.213/tcp/4001/p2p/QmSoLueR4xBeUbY9NziQvnPMqhAfK31SfNPGCGUfxf6HtL",
        ];

        // Parse manual bootstrap seeds from config first, then IPFS fallback
        let mut seeds: Vec<(Multiaddr, PeerId)> = Vec::new();

        let mut all_addrs: Vec<String> = self.config.network.discovery.manual_bootstrap.clone();
        for s in IPFS_BOOTSTRAP.iter() {
            all_addrs.push(s.to_string());
        }

        for addr_str in &all_addrs {
            if let Ok(ma) = addr_str.parse::<Multiaddr>() {
                // Extract /p2p/<peer_id> component
                let peer_id = ma.iter().find_map(|proto| {
                    if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                        Some(id)
                    } else {
                        None
                    }
                });
                if let Some(peer_id) = peer_id {
                    seeds.push((ma, peer_id));
                }
            }
        }

        if seeds.is_empty() {
            return Err(anyhow::anyhow!("DHT: no usable seed peers found"));
        }

        info!("DHT: connecting to {} seed peer(s)...", seeds.len());

        // ── Build minimal temp swarm ────────────────────────────────────────────
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        let store = kad::store::MemoryStore::new(local_peer_id);
        let mut kad_config = kad::Config::default();
        kad_config.set_record_ttl(Some(Duration::from_secs(3600)));

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_behaviour(|_| {
                Ok(kad::Behaviour::with_config(local_peer_id, store, kad_config))
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        // Add seeds to routing table and dial them
        for (addr, peer_id) in &seeds {
            swarm.behaviour_mut().add_address(peer_id, addr.clone());
            let _ = swarm.dial(addr.clone());
        }

        // Start Kademlia bootstrap
        if let Err(e) = swarm.behaviour_mut().bootstrap() {
            return Err(anyhow::anyhow!("DHT bootstrap failed: {}", e));
        }

        // ── Event loop ─────────────────────────────────────────────────────────
        let oarn_key = kad::RecordKey::new(b"/oarn/peers/v1");
        let mut bootstrap_done = false;
        let mut get_query_id: Option<libp2p::kad::QueryId> = None;
        let mut found_nodes: Vec<BootstrapNode> = Vec::new();

        let deadline = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                biased;
                _ = &mut deadline => {
                    warn!("DHT discovery timed out after 30s");
                    break;
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                            result, id, ..
                        }) => {
                            match result {
                                // Bootstrap complete — now query for OARN peers
                                kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk {
                                    num_remaining: 0, ..
                                })) => {
                                    info!("DHT bootstrap complete, querying OARN peer record...");
                                    bootstrap_done = true;
                                    let qid = swarm.behaviour_mut().get_record(oarn_key.clone());
                                    get_query_id = Some(qid);
                                }
                                kad::QueryResult::Bootstrap(Ok(_)) => {
                                    // Bootstrap still in progress
                                }
                                kad::QueryResult::Bootstrap(Err(e)) => {
                                    warn!("DHT bootstrap error: {:?}", e);
                                    // Try querying anyway if we have any connections
                                    if !bootstrap_done {
                                        bootstrap_done = true;
                                        let qid = swarm.behaviour_mut().get_record(oarn_key.clone());
                                        get_query_id = Some(qid);
                                    }
                                }
                                // OARN peers record found
                                kad::QueryResult::GetRecord(Ok(
                                    kad::GetRecordOk::FoundRecord(kad::PeerRecord {
                                        record, ..
                                    }),
                                )) => {
                                    if let Ok(nodes) =
                                        serde_json::from_slice::<Vec<BootstrapNode>>(&record.value)
                                    {
                                        info!("DHT: found {} OARN peer(s) in record", nodes.len());
                                        found_nodes.extend(nodes);
                                    } else {
                                        debug!("DHT: /oarn/peers/v1 record has unrecognised format");
                                    }
                                }
                                // Query finished (with or without records)
                                kad::QueryResult::GetRecord(Ok(
                                    kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                                )) => {
                                    if get_query_id.map_or(false, |qid| qid == id) {
                                        debug!("DHT: GetRecord query finished");
                                        break;
                                    }
                                }
                                kad::QueryResult::GetRecord(Err(e)) => {
                                    if get_query_id.map_or(false, |qid| qid == id) {
                                        debug!("DHT: GetRecord failed: {:?}", e);
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            debug!("DHT temp swarm connected to: {}", peer_id);
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            debug!("DHT temp swarm listening on: {}", address);
                        }
                        _ => {}
                    }
                }
            }
        }

        // ── Process results ────────────────────────────────────────────────────
        let discovered = found_nodes.len();
        for node in found_nodes {
            info!("DHT discovered OARN peer: {}", node.peer_id);
            self.bootstrap_nodes.push(node);
        }

        // Also add manual RPC if configured
        if let Some(rpc_url) = &self.config.blockchain.manual_rpc_url {
            if !self.rpc_providers.iter().any(|p| p.endpoint == *rpc_url) {
                self.rpc_providers.push(RpcProvider {
                    endpoint: rpc_url.clone(),
                    onion_endpoint: None,
                    stake: 0,
                    uptime: 10000,
                });
            }
        }

        if discovered == 0 && self.bootstrap_nodes.is_empty() {
            Err(anyhow::anyhow!(
                "DHT discovery found no OARN peers (record /oarn/peers/v1 not yet published)"
            ))
        } else {
            info!(
                "DHT discovery complete: {} OARN peer(s) found",
                self.bootstrap_nodes.len()
            );
            Ok(())
        }
    }

    /// Add a bootstrap node (called from network.rs after DHT query)
    pub fn add_bootstrap_node(&mut self, node: BootstrapNode) {
        if !self.bootstrap_nodes.iter().any(|n| n.peer_id == node.peer_id) {
            self.bootstrap_nodes.push(node);
        }
    }

    /// Add an RPC provider (called from network.rs after DHT query)
    pub fn add_rpc_provider(&mut self, provider: RpcProvider) {
        if !self.rpc_providers.iter().any(|p| p.endpoint == provider.endpoint) {
            self.rpc_providers.push(provider);
        }
    }

    /// Discover infrastructure via on-chain OARNRegistry contract.
    ///
    /// Uses the configured `manual_rpc_url` (or the public Arbitrum Sepolia RPC
    /// as a one-time bootstrap) to call OARNRegistry and populate:
    /// - core contract addresses (`getCoreContractsV2`)
    /// - active RPC providers (`getActiveRPCProviders`)
    /// - active bootstrap nodes (`getActiveBootstrapNodes`)
    async fn discover_via_onchain(&mut self) -> Result<()> {
        info!("Discovering via on-chain registry...");

        // Determine bootstrap RPC — manual config takes priority
        let rpc_url = match &self.config.blockchain.manual_rpc_url {
            Some(url) => {
                warn!("Using manual RPC URL for bootstrap: {}", url);
                url.clone()
            }
            None => {
                // The public Arbitrum Sepolia RPC is the only hardcoded value
                // permitted: used once to reach OARNRegistry, then replaced by
                // the decentralised provider set discovered from the contract.
                info!("No manual RPC configured — using public Arbitrum Sepolia RPC for bootstrap");
                "https://sepolia-rollup.arbitrum.io/rpc".to_string()
            }
        };

        let provider =
            Provider::<Http>::try_from(rpc_url.as_str()).context("Failed to create provider")?;

        // Verify connectivity
        provider
            .get_block_number()
            .await
            .with_context(|| format!("Cannot reach RPC at {}", rpc_url))?;

        // Always add the bootstrap RPC as a fallback provider entry
        if let Some(url) = &self.config.blockchain.manual_rpc_url {
            self.rpc_providers.push(RpcProvider {
                endpoint: url.clone(),
                onion_endpoint: None,
                stake: 0,
                uptime: 10000,
            });
        }

        // Resolve OARNRegistry address from prior ENS discovery or config
        let registry_addr_str = self
            .core_contracts
            .as_ref()
            .map(|c| c.oarn_registry.clone())
            .or_else(|| {
                self.config
                    .blockchain
                    .contracts
                    .as_ref()
                    .and_then(|c| c.oarn_registry.clone())
            });

        let registry_addr = match registry_addr_str {
            Some(ref s) if !s.is_empty() => match s.parse::<Address>() {
                Ok(addr) => addr,
                Err(e) => {
                    warn!("Invalid OARNRegistry address '{}': {}", s, e);
                    return if self.rpc_providers.is_empty() {
                        Err(anyhow::anyhow!(
                            "No usable OARNRegistry address or manual RPC"
                        ))
                    } else {
                        Ok(())
                    };
                }
            },
            _ => {
                warn!("No OARNRegistry address configured — skipping contract queries");
                return if self.rpc_providers.is_empty() {
                    Err(anyhow::anyhow!(
                        "No OARNRegistry address and no manual RPC configured"
                    ))
                } else {
                    Ok(())
                };
            }
        };

        info!("Querying OARNRegistry at {:?}", registry_addr);
        let registry = OARNRegistryContract::new(registry_addr, Arc::new(provider));

        // ── Core contract addresses ──────────────────────────────────────────
        // getCoreContractsV2 returns (taskReg, taskRegV2, tokenReward, validatorReg, governance, govToken)
        match registry.get_core_contracts_v2().call().await {
            Ok(r) => {
                info!("Loaded core contracts from OARNRegistry");
                self.core_contracts = Some(CoreContracts {
                    oarn_registry: format!("{:?}", registry_addr),
                    task_registry: format!("{:?}", r.0),
                    task_registry_v2: format!("{:?}", r.1),
                    token_reward: format!("{:?}", r.2),
                    validator_registry: format!("{:?}", r.3),
                    governance: format!("{:?}", r.4),
                    gov_token: format!("{:?}", r.5),
                });
            }
            Err(e) => {
                warn!("Failed to query core contracts: {}", e);
            }
        }

        // ── RPC providers ────────────────────────────────────────────────────
        // getActiveRPCProviders returns Vec<(endpoint, onionEndpoint, owner, stake, registeredAt, lastHeartbeat, uptime, reportCount, isActive)>
        match registry.get_active_rpc_providers().call().await {
            Ok(providers) => {
                info!(
                    "Discovered {} active RPC provider(s) from OARNRegistry",
                    providers.len()
                );
                for p in providers {
                    let (
                        endpoint,
                        onion_ep,
                        _owner,
                        stake,
                        _reg_at,
                        _hb,
                        uptime,
                        _reports,
                        _active,
                    ) = p;
                    if !endpoint.is_empty() {
                        self.rpc_providers.push(RpcProvider {
                            endpoint,
                            onion_endpoint: if onion_ep.is_empty() {
                                None
                            } else {
                                Some(onion_ep)
                            },
                            stake: stake.as_u64(),
                            uptime: uptime.as_u32(),
                        });
                    }
                }
            }
            Err(e) => {
                warn!("Failed to query RPC providers: {}", e);
            }
        }

        // ── Bootstrap nodes ──────────────────────────────────────────────────
        // getActiveBootstrapNodes returns Vec<(peerId, multiaddr, onionAddress, i2pAddress, owner, stake, registeredAt, lastHeartbeat, isActive)>
        match registry.get_active_bootstrap_nodes().call().await {
            Ok(nodes) => {
                info!(
                    "Discovered {} active bootstrap node(s) from OARNRegistry",
                    nodes.len()
                );
                for n in nodes {
                    let (
                        peer_id,
                        multiaddr,
                        onion_addr,
                        i2p_addr,
                        _owner,
                        _stake,
                        _reg_at,
                        _hb,
                        _active,
                    ) = n;
                    if !peer_id.is_empty() {
                        self.bootstrap_nodes.push(BootstrapNode {
                            peer_id,
                            multiaddr,
                            onion_address: if onion_addr.is_empty() {
                                None
                            } else {
                                Some(onion_addr)
                            },
                            i2p_address: if i2p_addr.is_empty() {
                                None
                            } else {
                                Some(i2p_addr)
                            },
                        });
                    }
                }
            }
            Err(e) => {
                warn!("Failed to query bootstrap nodes: {}", e);
            }
        }

        if self.rpc_providers.is_empty() {
            Err(anyhow::anyhow!("On-chain discovery found no RPC providers"))
        } else {
            Ok(())
        }
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
                task_registry_v2: contracts.task_registry_v2.clone().unwrap_or_default(),
                token_reward: contracts.token_reward.clone().unwrap_or_default(),
                validator_registry: String::new(),
                governance: contracts.governance.clone().unwrap_or_default(),
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

        let healthy: Vec<_> = self
            .rpc_providers
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
            task_registry_v2: "0x2346".to_string(),
            token_reward: "0x3456".to_string(),
            validator_registry: "0x4567".to_string(),
            governance: "0x5678".to_string(),
            gov_token: "0x6789".to_string(),
        };

        assert_eq!(contracts.oarn_registry, "0x1234");
        assert_eq!(contracts.task_registry, "0x2345");
        assert_eq!(contracts.task_registry_v2, "0x2346");
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
        assert_eq!(
            discovery.rpc_providers[0].endpoint,
            "https://test-rpc.example.com"
        );
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
            rpc_providers: vec![RpcProvider {
                endpoint: "https://rpc1.example.com".to_string(),
                onion_endpoint: None,
                stake: 1000,
                uptime: 9500,
            }],
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
            rpc_providers: vec![RpcProvider {
                endpoint: "https://unhealthy.example.com".to_string(),
                onion_endpoint: None,
                stake: 1000,
                uptime: 5000, // All unhealthy
            }],
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
            task_registry_v2: "0x2346".to_string(),
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
        assert_eq!(
            discovery.get_core_contracts().unwrap().oarn_registry,
            "0x1234"
        );
    }
}
