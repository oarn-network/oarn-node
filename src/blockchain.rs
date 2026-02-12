//! Blockchain integration module
//!
//! Handles communication with Arbitrum smart contracts.
//! Uses discovered RPC providers - never hardcoded URLs.

use anyhow::{Context, Result};
use ethers::{
    prelude::*,
    providers::{Http, Provider, Middleware},
    types::{Address, U256},
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::Config;
use crate::discovery::Discovery;

/// Blockchain events
#[derive(Debug)]
pub enum BlockchainEvent {
    TaskCreated(u64),
    TaskCompleted(u64),
    RewardReceived(u64),
}

/// Blockchain client for interacting with OARN contracts
pub struct BlockchainClient {
    provider: Arc<Provider<Http>>,
    chain_id: u64,
    event_rx: mpsc::Receiver<BlockchainEvent>,
    event_tx: mpsc::Sender<BlockchainEvent>,

    // Contract addresses (discovered, not hardcoded)
    task_registry_address: Option<Address>,
    token_reward_address: Option<Address>,
    oarn_registry_address: Option<Address>,
}

impl BlockchainClient {
    /// Create a new blockchain client using discovered RPC providers
    pub async fn new(config: &Config, discovery: &Discovery) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::channel(100);

        // Get RPC provider from discovery (NOT hardcoded!)
        let rpc = discovery.get_random_rpc().await?;
        info!("Connecting to RPC: {}", rpc.endpoint);

        let provider = Provider::<Http>::try_from(&rpc.endpoint)
            .context("Failed to create provider")?;

        // Verify chain ID matches config
        let chain_id = provider.get_chainid().await?.as_u64();
        if chain_id != config.blockchain.chain_id {
            warn!(
                "Chain ID mismatch: expected {}, got {}",
                config.blockchain.chain_id, chain_id
            );
        }

        info!("Connected to chain ID: {}", chain_id);

        // Get contract addresses from discovery
        let (task_registry_address, token_reward_address, oarn_registry_address) =
            if let Some(contracts) = discovery.get_core_contracts() {
                (
                    contracts.task_registry.parse().ok(),
                    contracts.token_reward.parse().ok(),
                    contracts.oarn_registry.parse().ok(),
                )
            } else {
                (None, None, None)
            };

        Ok(Self {
            provider: Arc::new(provider),
            chain_id,
            event_rx,
            event_tx,
            task_registry_address,
            token_reward_address,
            oarn_registry_address,
        })
    }

    /// Get chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Get next blockchain event
    pub async fn next_event(&mut self) -> Option<BlockchainEvent> {
        self.event_rx.recv().await
    }

    /// Get current block number
    pub async fn get_block_number(&self) -> Result<u64> {
        let block = self.provider.get_block_number().await?;
        Ok(block.as_u64())
    }

    /// Get ETH balance
    pub async fn get_eth_balance(&self, address: Address) -> Result<U256> {
        let balance = self.provider.get_balance(address, None).await?;
        Ok(balance)
    }

    /// Query available tasks from TaskRegistry
    pub async fn get_available_tasks(&self) -> Result<Vec<TaskInfo>> {
        let _task_registry = self.task_registry_address
            .context("TaskRegistry address not discovered")?;

        // TODO: Call TaskRegistry.getAvailableTasks()
        // For now, return empty
        Ok(vec![])
    }

    /// Claim a task
    pub async fn claim_task(&self, _task_id: u64, _wallet: &LocalWallet) -> Result<TxHash> {
        let _task_registry = self.task_registry_address
            .context("TaskRegistry address not discovered")?;

        // TODO: Call TaskRegistry.claimTask(taskId)
        // For now, return placeholder
        Err(anyhow::anyhow!("Not implemented"))
    }

    /// Submit task result
    pub async fn submit_result(
        &self,
        _task_id: u64,
        _result_hash: [u8; 32],
        _wallet: &LocalWallet,
    ) -> Result<TxHash> {
        let _task_registry = self.task_registry_address
            .context("TaskRegistry address not discovered")?;

        // TODO: Call TaskRegistry.submitResult(taskId, resultHash)
        Err(anyhow::anyhow!("Not implemented"))
    }

    /// Get COMP token balance
    pub async fn get_comp_balance(&self, _address: Address) -> Result<U256> {
        let _token_reward = self.token_reward_address
            .context("TokenReward address not discovered")?;

        // TODO: Call COMPToken.balanceOf(address)
        Ok(U256::zero())
    }

    /// Get GOV token balance
    pub async fn get_gov_balance(&self, _address: Address) -> Result<U256> {
        // TODO: Implement
        Ok(U256::zero())
    }

    /// Subscribe to contract events
    pub async fn subscribe_events(&self) -> Result<()> {
        // TODO: Set up event subscription via WebSocket or polling
        Ok(())
    }

    /// Verify RPC provider is healthy
    pub async fn health_check(&self) -> Result<bool> {
        match self.provider.get_block_number().await {
            Ok(_) => Ok(true),
            Err(e) => {
                warn!("RPC health check failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Switch to a different RPC provider
    pub async fn switch_rpc(&mut self, discovery: &Discovery) -> Result<()> {
        let rpc = discovery.get_random_rpc().await?;
        info!("Switching to RPC: {}", rpc.endpoint);

        let provider = Provider::<Http>::try_from(&rpc.endpoint)?;
        self.provider = Arc::new(provider);

        Ok(())
    }
}

/// Task information from blockchain
#[derive(Debug, Clone)]
pub struct TaskInfo {
    pub id: u64,
    pub requester: Address,
    pub model_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub reward_per_node: U256,
    pub required_nodes: u32,
    pub deadline: u64,
}
