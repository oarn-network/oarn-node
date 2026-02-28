//! Blockchain integration module
//!
//! Handles communication with Arbitrum smart contracts.
//! Uses discovered RPC providers - never hardcoded URLs.

use anyhow::{Context, Result};
use ethers::{
    prelude::*,
    providers::{Http, Provider, Middleware},
    types::{Address, U256, TxHash},
    signers::LocalWallet,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, debug};

use crate::config::Config;
use crate::discovery::Discovery;

// Generate contract bindings from ABI
abigen!(
    TaskRegistryContract,
    r#"[
        function taskCount() external view returns (uint256)
        function tasks(uint256 taskId) external view returns (uint256 id, address requester, bytes32 modelHash, bytes32 inputHash, string modelRequirements, uint256 rewardPerNode, uint256 requiredNodes, uint256 completedNodes, uint256 deadline, uint8 status, uint8 mode, uint256 createdAt)
        function claimTask(uint256 taskId) external
        function submitResult(uint256 taskId, bytes32 resultHash) external
        function submitTask(bytes32 modelHash, bytes32 inputHash, string modelRequirements, uint256 rewardPerNode, uint256 requiredNodes, uint256 deadline) external payable returns (uint256)
        function hasClaimedTask(uint256 taskId, address node) external view returns (bool)
        function hasSubmittedResult(uint256 taskId, address node) external view returns (bool)
        function minRewardPerNode() external view returns (uint256)
        function getTask(uint256 taskId) external view returns (uint256 id, address requester, bytes32 modelHash, bytes32 inputHash, string modelRequirements, uint256 rewardPerNode, uint256 requiredNodes, uint256 completedNodes, uint256 deadline, uint8 status, uint8 mode, uint256 createdAt)
        event TaskCreated(uint256 indexed taskId, address indexed requester, bytes32 modelHash, uint256 rewardPerNode, uint256 requiredNodes, uint8 mode)
        event TaskClaimed(uint256 indexed taskId, address indexed node)
        event ResultSubmitted(uint256 indexed taskId, address indexed node, bytes32 resultHash)
        event TaskCompleted(uint256 indexed taskId, uint256 totalRewards)
        event RewardDistributed(uint256 indexed taskId, address indexed node, uint256 amount)
    ]"#
);

// ERC20 token bindings
abigen!(
    ERC20Token,
    r#"[
        function name() external view returns (string)
        function symbol() external view returns (string)
        function decimals() external view returns (uint8)
        function totalSupply() external view returns (uint256)
        function balanceOf(address account) external view returns (uint256)
    ]"#
);

// GOV token with voting
abigen!(
    GOVToken,
    r#"[
        function name() external view returns (string)
        function symbol() external view returns (string)
        function balanceOf(address account) external view returns (uint256)
        function getVotes(address account) external view returns (uint256)
        function delegates(address account) external view returns (address)
        function delegate(address delegatee) external
    ]"#
);

// Governance contract bindings
abigen!(
    GovernanceContract,
    r#"[
        function proposalCount() external view returns (uint256)
        function getProposalId(uint256 index) external view returns (uint256)
        function getProposalSummary(uint256 proposalId) external view returns (string title, string description, address proposer, uint256 startBlock, uint256 endBlock, uint8 status, uint256 forVotes, uint256 againstVotes, uint256 abstainVotes)
        function state(uint256 proposalId) external view returns (uint8)
        function hasVoted(uint256 proposalId, address account) external view returns (bool)
        function castVote(uint256 proposalId, uint8 support) external returns (uint256)
        function proposeWithMetadata(address[] targets, uint256[] values, bytes[] calldatas, string title, string description) external returns (uint256)
        function votingDelay() external view returns (uint256)
        function votingPeriod() external view returns (uint256)
        function proposalThreshold() external view returns (uint256)
    ]"#
);

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
    governance_address: Option<Address>,
    gov_token_address: Option<Address>,

    // Contract instances
    task_registry: Option<TaskRegistryContract<Provider<Http>>>,
    governance: Option<GovernanceContract<Provider<Http>>>,
    gov_token: Option<GOVToken<Provider<Http>>>,
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
        let (task_registry_address, token_reward_address, oarn_registry_address, governance_address, gov_token_address) =
            if let Some(contracts) = discovery.get_core_contracts() {
                (
                    contracts.task_registry.parse().ok(),
                    contracts.token_reward.parse().ok(),
                    contracts.oarn_registry.parse().ok(),
                    contracts.governance.parse().ok(),
                    contracts.gov_token.parse().ok(),
                )
            } else {
                (None, None, None, None, None)
            };

        let provider = Arc::new(provider);

        // Initialize contract instances if addresses are available
        let task_registry = task_registry_address.map(|addr| {
            TaskRegistryContract::new(addr, provider.clone())
        });

        let governance = governance_address.map(|addr| {
            GovernanceContract::new(addr, provider.clone())
        });

        let gov_token = gov_token_address.map(|addr| {
            GOVToken::new(addr, provider.clone())
        });

        if task_registry.is_some() {
            info!("TaskRegistry contract initialized at {:?}", task_registry_address);
        }
        if governance.is_some() {
            info!("Governance contract initialized at {:?}", governance_address);
        }

        Ok(Self {
            provider,
            chain_id,
            event_rx,
            event_tx,
            task_registry_address,
            token_reward_address,
            oarn_registry_address,
            governance_address,
            gov_token_address,
            task_registry,
            governance,
            gov_token,
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
        let contract = self.task_registry.as_ref()
            .context("TaskRegistry contract not initialized")?;

        info!("Querying available tasks from TaskRegistry...");

        // Get total task count first
        let task_count = contract.task_count().call().await
            .context("Failed to call taskCount")?;

        info!("Total task count on-chain: {}", task_count);

        if task_count.is_zero() {
            return Ok(vec![]);
        }

        // Query individual tasks and filter available ones
        let mut result = Vec::new();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        info!("Current Unix time: {}", current_time);

        for i in 1..=task_count.as_u64() {
            match contract.tasks(U256::from(i)).call().await {
                Ok(task) => {
                    // task is a tuple: (id, requester, modelHash, inputHash, modelRequirements, rewardPerNode, requiredNodes, completedNodes, deadline, status, mode, createdAt)
                    let status = task.9; // status field
                    let deadline = task.8.as_u64(); // deadline field

                    info!("Task #{}: status={}, deadline={}, current_time={}", i, status, deadline, current_time);

                    // Only include Pending (0) or Active (1) tasks that haven't expired
                    if (status == 0 || status == 1) && deadline > current_time {
                        info!("Task #{} is available!", i);
                        result.push(TaskInfo {
                            id: task.0.as_u64(),
                            requester: task.1,
                            model_hash: task.2,
                            input_hash: task.3,
                            reward_per_node: task.5,
                            required_nodes: task.6.as_u32(),
                            deadline,
                        });
                    } else {
                        info!("Task #{} is NOT available (status={}, expired={})", i, status, deadline <= current_time);
                    }
                }
                Err(e) => {
                    warn!("Failed to get task #{}: {}", i, e);
                }
            }
        }

        info!("Found {} available tasks", result.len());
        Ok(result)
    }

    /// Check if a task has been claimed by this node
    pub async fn has_claimed_task(&self, task_id: u64, node_address: Address) -> Result<bool> {
        let contract = self.task_registry.as_ref()
            .context("TaskRegistry contract not initialized")?;

        let claimed = contract.has_claimed_task(U256::from(task_id), node_address).call().await?;
        Ok(claimed)
    }

    /// Check if a result has been submitted by this node
    pub async fn has_submitted_result(&self, task_id: u64, node_address: Address) -> Result<bool> {
        let contract = self.task_registry.as_ref()
            .context("TaskRegistry contract not initialized")?;

        let submitted = contract.has_submitted_result(U256::from(task_id), node_address).call().await?;
        Ok(submitted)
    }

    /// Claim a task
    pub async fn claim_task(&self, task_id: u64, wallet: &LocalWallet) -> Result<TxHash> {
        let contract_address = self.task_registry_address
            .context("TaskRegistry address not discovered")?;

        info!("Claiming task #{}...", task_id);

        // Create a signing client
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.clone().with_chain_id(self.chain_id),
        ));

        let contract = TaskRegistryContract::new(contract_address, client);

        // Create the contract call
        let call = contract.claim_task(U256::from(task_id));

        // Send and await the transaction
        let pending_tx = call.send().await?;
        let tx_hash = pending_tx.tx_hash();

        info!("Claim transaction sent: {:?}", tx_hash);

        // Wait for confirmation
        let receipt = pending_tx.await?
            .context("Transaction failed")?;

        info!("Task #{} claimed successfully in block {:?}", task_id, receipt.block_number);
        Ok(tx_hash)
    }

    /// Submit task result
    pub async fn submit_result(
        &self,
        task_id: u64,
        result_hash: [u8; 32],
        wallet: &LocalWallet,
    ) -> Result<TxHash> {
        let contract_address = self.task_registry_address
            .context("TaskRegistry address not discovered")?;

        info!("Submitting result for task #{}...", task_id);

        // Create a signing client
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.clone().with_chain_id(self.chain_id),
        ));

        let contract = TaskRegistryContract::new(contract_address, client);

        // Create the contract call
        let call = contract.submit_result(U256::from(task_id), result_hash);

        // Send and await the transaction
        let pending_tx = call.send().await?;
        let tx_hash = pending_tx.tx_hash();

        info!("Submit result transaction sent: {:?}", tx_hash);

        // Wait for confirmation
        let receipt = pending_tx.await?
            .context("Transaction failed")?;

        info!("Result submitted for task #{} in block {:?}", task_id, receipt.block_number);
        Ok(tx_hash)
    }

    /// Submit a new task to the network
    pub async fn submit_task(
        &self,
        model_hash: [u8; 32],
        input_hash: [u8; 32],
        model_requirements: &str,
        reward_per_node: U256,
        required_nodes: u64,
        deadline: u64,
        wallet: &LocalWallet,
    ) -> Result<(TxHash, u64)> {
        let contract_address = self.task_registry_address
            .context("TaskRegistry address not discovered")?;

        info!("Submitting new task to TaskRegistry...");
        info!("  Model hash: 0x{}", hex::encode(model_hash));
        info!("  Input hash: 0x{}", hex::encode(input_hash));
        info!("  Reward per node: {} ETH", ethers::utils::format_ether(reward_per_node));
        info!("  Required nodes: {}", required_nodes);

        // Calculate total cost
        let total_cost = reward_per_node * U256::from(required_nodes);
        info!("  Total cost: {} ETH", ethers::utils::format_ether(total_cost));

        // Create a signing client
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.clone().with_chain_id(self.chain_id),
        ));

        let contract = TaskRegistryContract::new(contract_address, client);

        // Create the contract call with value
        let call = contract
            .submit_task(
                model_hash,
                input_hash,
                model_requirements.to_string(),
                reward_per_node,
                U256::from(required_nodes),
                U256::from(deadline),
            )
            .value(total_cost);

        // Send and await the transaction
        let pending_tx = call.send().await
            .context("Failed to send submitTask transaction")?;
        let tx_hash = pending_tx.tx_hash();

        info!("Task submission transaction sent: {:?}", tx_hash);

        // Wait for confirmation
        let receipt = pending_tx.await?
            .context("Transaction failed")?;

        info!("Task submitted in block {:?}", receipt.block_number);

        // Get the new task count to determine the task ID
        let task_id = self.get_task_count().await?;

        info!("Task created with ID: {}", task_id);
        Ok((tx_hash, task_id))
    }

    /// Get detailed task information
    pub async fn get_task_details(&self, task_id: u64) -> Result<TaskDetails> {
        let contract = self.task_registry.as_ref()
            .context("TaskRegistry contract not initialized")?;

        // Use the tasks mapping which we know works
        let task = contract.tasks(U256::from(task_id)).call().await
            .context("Failed to get task details")?;

        // Check if task exists (id will be 0 if not found)
        if task.0.is_zero() {
            anyhow::bail!("Task not found");
        }

        Ok(TaskDetails {
            id: task.0.as_u64(),
            requester: task.1,
            model_hash: task.2,
            input_hash: task.3,
            model_requirements: task.4,
            reward_per_node: task.5,
            required_nodes: task.6.as_u32(),
            completed_nodes: task.7.as_u32(),
            deadline: task.8.as_u64(),
            status: task.9,
            mode: task.10,
            created_at: task.11.as_u64(),
        })
    }

    /// Get minimum reward per node
    pub async fn get_min_reward(&self) -> Result<U256> {
        let contract = self.task_registry.as_ref()
            .context("TaskRegistry contract not initialized")?;

        let min_reward = contract.min_reward_per_node().call().await?;
        Ok(min_reward)
    }

    /// Get task count
    pub async fn get_task_count(&self) -> Result<u64> {
        let contract = self.task_registry.as_ref()
            .context("TaskRegistry contract not initialized")?;

        let count = contract.task_count().call().await?;
        Ok(count.as_u64())
    }

    /// Get COMP token balance
    pub async fn get_comp_balance(&self, address: Address) -> Result<U256> {
        let token_address = self.token_reward_address
            .context("COMP token address not discovered")?;

        let token = ERC20Token::new(token_address, self.provider.clone());
        let balance = token.balance_of(address).call().await?;
        Ok(balance)
    }

    /// Get GOV token balance
    pub async fn get_gov_balance(&self, address: Address) -> Result<U256> {
        // GOV token address would need to be discovered/configured
        // For now, return zero since we don't have the address stored
        let _ = address;
        Ok(U256::zero())
    }

    /// Get node's total earnings (ETH rewards from completed tasks)
    pub async fn get_node_earnings(&self, address: Address) -> Result<NodeEarnings> {
        let eth_balance = self.get_eth_balance(address).await?;
        let comp_balance = self.get_comp_balance(address).await.unwrap_or(U256::zero());

        // Count completed tasks by checking which tasks this node has submitted results for
        let mut tasks_completed = 0u64;
        let task_count = self.get_task_count().await.unwrap_or(0);

        for task_id in 1..=task_count {
            if self.has_submitted_result(task_id, address).await.unwrap_or(false) {
                tasks_completed += 1;
            }
        }

        Ok(NodeEarnings {
            eth_balance,
            comp_balance,
            tasks_completed,
        })
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

    // ============ Governance Functions ============

    /// Get proposal count
    pub async fn get_proposal_count(&self) -> Result<u64> {
        let contract = self.governance.as_ref()
            .context("Governance contract not initialized")?;

        let count = contract.proposal_count().call().await?;
        Ok(count.as_u64())
    }

    /// Get proposal by index
    pub async fn get_proposal(&self, index: u64) -> Result<Proposal> {
        let contract = self.governance.as_ref()
            .context("Governance contract not initialized")?;

        let proposal_id = contract.get_proposal_id(U256::from(index)).call().await?;
        let summary = contract.get_proposal_summary(proposal_id).call().await?;

        Ok(Proposal {
            id: format!("{}", proposal_id),
            title: summary.0,
            description: summary.1,
            proposer: summary.2,
            start_block: summary.3.as_u64(),
            end_block: summary.4.as_u64(),
            status: summary.5,
            for_votes: summary.6,
            against_votes: summary.7,
            abstain_votes: summary.8,
        })
    }

    /// Get all proposals
    pub async fn get_proposals(&self, limit: u32) -> Result<Vec<Proposal>> {
        let count = self.get_proposal_count().await?;
        let mut proposals = Vec::new();

        let start = if count > limit as u64 { count - limit as u64 } else { 0 };

        for i in start..count {
            match self.get_proposal(i).await {
                Ok(p) => proposals.push(p),
                Err(e) => debug!("Failed to get proposal {}: {}", i, e),
            }
        }

        Ok(proposals)
    }

    /// Get voting power
    pub async fn get_voting_power(&self, address: Address) -> Result<U256> {
        let contract = self.gov_token.as_ref()
            .context("GOV token contract not initialized")?;

        let votes = contract.get_votes(address).call().await?;
        Ok(votes)
    }

    /// Get GOV token balance
    pub async fn get_gov_token_balance(&self, address: Address) -> Result<U256> {
        let contract = self.gov_token.as_ref()
            .context("GOV token contract not initialized")?;

        let balance = contract.balance_of(address).call().await?;
        Ok(balance)
    }

    /// Get current delegate
    pub async fn get_delegate(&self, address: Address) -> Result<Address> {
        let contract = self.gov_token.as_ref()
            .context("GOV token contract not initialized")?;

        let delegate = contract.delegates(address).call().await?;
        Ok(delegate)
    }

    /// Delegate voting power
    pub async fn delegate_votes(&self, to: Address, wallet: &LocalWallet) -> Result<TxHash> {
        let token_address = self.gov_token_address
            .context("GOV token address not discovered")?;

        info!("Delegating voting power to {:?}...", to);

        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.clone().with_chain_id(self.chain_id),
        ));

        let contract = GOVToken::new(token_address, client);
        let call = contract.delegate(to);
        let pending_tx = call.send().await?;
        let tx_hash = pending_tx.tx_hash();

        info!("Delegation transaction sent: {:?}", tx_hash);

        pending_tx.await?.context("Delegation failed")?;
        Ok(tx_hash)
    }

    /// Cast vote on a proposal
    pub async fn cast_vote(
        &self,
        proposal_id: &str,
        support: u8, // 0 = Against, 1 = For, 2 = Abstain
        wallet: &LocalWallet,
    ) -> Result<TxHash> {
        let gov_address = self.governance_address
            .context("Governance address not discovered")?;

        let proposal_id_u256 = U256::from_dec_str(proposal_id)
            .context("Invalid proposal ID")?;

        info!("Casting vote on proposal {}...", proposal_id);

        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.clone().with_chain_id(self.chain_id),
        ));

        let contract = GovernanceContract::new(gov_address, client);
        let call = contract.cast_vote(proposal_id_u256, support);
        let pending_tx = call.send().await?;
        let tx_hash = pending_tx.tx_hash();

        info!("Vote transaction sent: {:?}", tx_hash);

        pending_tx.await?.context("Vote failed")?;
        Ok(tx_hash)
    }

    /// Check if address has voted on proposal
    pub async fn has_voted(&self, proposal_id: &str, address: Address) -> Result<bool> {
        let contract = self.governance.as_ref()
            .context("Governance contract not initialized")?;

        let proposal_id_u256 = U256::from_dec_str(proposal_id)
            .context("Invalid proposal ID")?;

        let voted = contract.has_voted(proposal_id_u256, address).call().await?;
        Ok(voted)
    }

    /// Create a proposal
    pub async fn create_proposal(
        &self,
        title: &str,
        description: &str,
        target: Address,
        calldata: Vec<u8>,
        value: U256,
        wallet: &LocalWallet,
    ) -> Result<(TxHash, String)> {
        let gov_address = self.governance_address
            .context("Governance address not discovered")?;

        info!("Creating proposal: {}", title);

        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.clone().with_chain_id(self.chain_id),
        ));

        let contract = GovernanceContract::new(gov_address, client);

        let call = contract.propose_with_metadata(
            vec![target],
            vec![value],
            vec![calldata.into()],
            title.to_string(),
            description.to_string(),
        );
        let pending_tx = call.send().await?;
        let tx_hash = pending_tx.tx_hash();
        info!("Proposal transaction sent: {:?}", tx_hash);

        let receipt = pending_tx.await?.context("Proposal creation failed")?;

        // Get proposal ID from the new count
        let count = self.get_proposal_count().await?;
        let proposal_id = format!("{}", count);

        info!("Proposal created in block {:?}", receipt.block_number);
        Ok((tx_hash, proposal_id))
    }
}

/// Proposal information
#[derive(Debug, Clone)]
pub struct Proposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub proposer: Address,
    pub start_block: u64,
    pub end_block: u64,
    pub status: u8,
    pub for_votes: U256,
    pub against_votes: U256,
    pub abstain_votes: U256,
}

impl Proposal {
    /// Get status as string
    pub fn status_str(&self) -> &'static str {
        match self.status {
            0 => "Pending",
            1 => "Active",
            2 => "Canceled",
            3 => "Defeated",
            4 => "Succeeded",
            5 => "Queued",
            6 => "Expired",
            7 => "Executed",
            _ => "Unknown",
        }
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

/// Node earnings summary
#[derive(Debug, Clone)]
pub struct NodeEarnings {
    pub eth_balance: U256,
    pub comp_balance: U256,
    pub tasks_completed: u64,
}

/// Detailed task information
#[derive(Debug, Clone)]
pub struct TaskDetails {
    pub id: u64,
    pub requester: Address,
    pub model_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub model_requirements: String,
    pub reward_per_node: U256,
    pub required_nodes: u32,
    pub completed_nodes: u32,
    pub deadline: u64,
    pub status: u8,
    pub mode: u8,
    pub created_at: u64,
}

impl TaskDetails {
    /// Get status as human-readable string
    pub fn status_str(&self) -> &'static str {
        match self.status {
            0 => "Pending",
            1 => "Active",
            2 => "Completed",
            3 => "Cancelled",
            4 => "Expired",
            _ => "Unknown",
        }
    }

    /// Get mode as human-readable string
    pub fn mode_str(&self) -> &'static str {
        match self.mode {
            0 => "Standard",
            1 => "ValidatorRouted",
            _ => "Unknown",
        }
    }
}
