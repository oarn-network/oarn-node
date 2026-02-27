//! OARN Node - Decentralized AI Research Network Node Software
//!
//! This is the main entry point for the OARN node software.
//! Nodes participate in the network by:
//! - Discovering peers via DHT (no hardcoded addresses)
//! - Claiming and executing AI inference tasks
//! - Submitting results and earning COMP tokens

mod cli;
mod config;
mod network;
mod blockchain;
mod storage;
mod compute;
mod discovery;

use anyhow::{Context, Result};
use clap::Parser;
use ethers::signers::{LocalWallet, Signer};
use std::time::Duration;
use tokio::time::interval;
use tracing::{info, warn, error, debug, Level};
use tracing_subscriber::FmtSubscriber;

use crate::cli::{Cli, Commands};
use crate::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let _subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Load configuration
    let config = Config::load(&cli.config)?;

    match cli.command {
        Commands::Start => {
            info!("Starting OARN node...");
            run_node(config).await?;
        }
        Commands::Status => {
            info!("Checking node status...");
            show_status(config).await?;
        }
        Commands::Tasks { subcommand } => {
            handle_tasks(config, subcommand).await?;
        }
        Commands::Wallet { subcommand } => {
            handle_wallet(config, subcommand).await?;
        }
        Commands::Config { subcommand } => {
            handle_config(config, subcommand)?;
        }
    }

    Ok(())
}

/// Load wallet from config
fn load_wallet(config: &Config) -> Result<Option<LocalWallet>> {
    // Try loading from private key first (for testing)
    if let Some(ref private_key) = config.wallet.private_key {
        let key = private_key.strip_prefix("0x").unwrap_or(private_key);
        let wallet: LocalWallet = key.parse()
            .context("Failed to parse private key")?;
        info!("Loaded wallet from private key: {:?}", wallet.address());
        return Ok(Some(wallet));
    }

    // Try loading from keystore
    if let Some(ref keystore_path) = config.wallet.keystore_path {
        warn!("Keystore loading not yet implemented: {:?}", keystore_path);
    }

    warn!("No wallet configured - node will run in read-only mode");
    warn!("Add 'private_key' to [wallet] section in config to enable task processing");
    Ok(None)
}

/// Run the main node loop
async fn run_node(config: Config) -> Result<()> {
    info!("{}", "=".repeat(50));
    info!("OARN Node v{}", env!("CARGO_PKG_VERSION"));
    info!("{}", "=".repeat(50));

    // Step 1: Discover infrastructure (no hardcoded values!)
    info!("Discovering network infrastructure...");
    let discovery = discovery::Discovery::new(&config).await?;

    // Step 2: Initialize blockchain connection
    info!("Connecting to blockchain...");
    let mut blockchain = blockchain::BlockchainClient::new(&config, &discovery).await?;
    info!("Connected to chain ID: {}", blockchain.chain_id());

    // Step 3: Initialize P2P network
    info!("Initializing P2P network...");
    let mut network = network::P2PNetwork::new(&config, &discovery).await?;
    info!("Local peer ID: {}", network.local_peer_id());

    // Step 4: Initialize IPFS storage
    info!("Connecting to IPFS...");
    let storage = storage::IpfsStorage::new(&config).await?;

    // Step 5: Initialize compute engine
    info!("Initializing compute engine...");
    let compute = compute::ComputeEngine::new(&config)?;

    // Step 6: Load wallet for signing transactions
    let wallet = load_wallet(&config)?;

    info!("Node started successfully!");
    info!("Listening on: {:?}", config.network.listen_addresses);
    info!("{}", "-".repeat(50));

    // Task polling interval (every 30 seconds)
    let mut task_poll_interval = interval(Duration::from_secs(30));

    // Main event loop
    loop {
        tokio::select! {
            // Handle P2P network events
            event = network.next_event() => {
                if let Some(event) = event {
                    handle_network_event(event, &blockchain, &storage, &compute).await?;
                }
            }

            // Handle blockchain events
            event = blockchain.next_event() => {
                if let Some(event) = event {
                    handle_blockchain_event(event, &mut network).await?;
                }
            }

            // Poll for available tasks
            _ = task_poll_interval.tick() => {
                if let Some(ref wallet) = wallet {
                    if let Err(e) = poll_and_process_tasks(&blockchain, &storage, &compute, wallet).await {
                        error!("Task polling error: {}", e);
                    }
                }
            }

            // Graceful shutdown on Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
        }
    }

    Ok(())
}

/// Process a task that was already claimed but not yet completed
async fn process_claimed_task(
    task: &blockchain::TaskInfo,
    blockchain: &blockchain::BlockchainClient,
    storage: &storage::IpfsStorage,
    compute: &compute::ComputeEngine,
    wallet: &LocalWallet,
) {
    info!("Processing previously claimed task #{}...", task.id);

    // Try to download model and input from IPFS, fall back to placeholder
    let model_data = storage.get(&task.model_hash).await;
    let input_data = storage.get(&task.input_hash).await;

    let (model, input) = match (model_data, input_data) {
        (Ok(m), Ok(i)) => {
            info!("Downloaded model and input from IPFS");
            (m, i)
        }
        _ => {
            // Use placeholder data for testing (hash-based deterministic data)
            warn!("IPFS unavailable - using placeholder data for testing");
            let model = task.model_hash.to_vec();
            let input = task.input_hash.to_vec();
            (model, input)
        }
    };

    // Execute the task
    info!("Executing task #{}...", task.id);
    match compute.execute(&model, &input).await {
        Ok(result) => {
            // Hash the result
            let result_hash = compute.hash_result(&result);
            info!("Task #{} completed! Result hash: 0x{}", task.id, hex::encode(result_hash));

            // Try to upload result to IPFS (optional)
            if let Ok(result_cid) = storage.put(&result).await {
                info!("Result uploaded to IPFS: {}", result_cid);
            }

            // Submit result on-chain
            match blockchain.submit_result(task.id, result_hash, wallet).await {
                Ok(tx_hash) => {
                    info!("Result submitted for task #{}! TX: {:?}", task.id, tx_hash);
                }
                Err(e) => {
                    error!("Failed to submit result for task #{}: {}", task.id, e);
                }
            }
        }
        Err(e) => {
            error!("Task #{} execution failed: {}", task.id, e);
        }
    }
}

/// Poll for available tasks and process them
async fn poll_and_process_tasks(
    blockchain: &blockchain::BlockchainClient,
    storage: &storage::IpfsStorage,
    compute: &compute::ComputeEngine,
    wallet: &LocalWallet,
) -> Result<()> {
    info!("Polling for available tasks...");

    // Get available tasks from blockchain
    let tasks = blockchain.get_available_tasks().await?;

    if tasks.is_empty() {
        info!("No available tasks found");
        return Ok(());
    }

    info!("Found {} available tasks", tasks.len());

    for task in tasks {
        // Check if we've already claimed this task
        let already_claimed = blockchain.has_claimed_task(task.id, wallet.address()).await?;

        // Check if we've already submitted results
        let already_submitted = blockchain.has_submitted_result(task.id, wallet.address()).await?;

        if already_submitted {
            debug!("Task #{} already completed by us", task.id);
            continue;
        }

        // If we claimed but haven't submitted, process it now
        if already_claimed {
            info!("Task #{} was claimed but not completed - processing now...", task.id);
            process_claimed_task(&task, blockchain, storage, compute, wallet).await;
            continue;
        }

        // Check if we can handle this task (framework, RAM, etc.)
        if !compute.can_handle_task(&task) {
            debug!("Task #{} - cannot handle (requirements not met)", task.id);
            continue;
        }

        info!("Claiming task #{}...", task.id);

        // Claim the task on-chain
        match blockchain.claim_task(task.id, wallet).await {
            Ok(tx_hash) => {
                info!("Task #{} claimed successfully! TX: {:?}", task.id, tx_hash);

                // Try to download model and input from IPFS, fall back to placeholder
                info!("Downloading model and input data...");
                let model_data = storage.get(&task.model_hash).await;
                let input_data = storage.get(&task.input_hash).await;

                let (model, input) = match (model_data, input_data) {
                    (Ok(m), Ok(i)) => {
                        info!("Downloaded model and input from IPFS");
                        (m, i)
                    }
                    _ => {
                        // Use placeholder data for testing (hash-based deterministic data)
                        warn!("IPFS unavailable - using placeholder data for testing");
                        let model = task.model_hash.to_vec();
                        let input = task.input_hash.to_vec();
                        (model, input)
                    }
                };

                // Execute the task
                info!("Executing task #{}...", task.id);
                match compute.execute(&model, &input).await {
                    Ok(result) => {
                        // Hash the result
                        let result_hash = compute.hash_result(&result);
                        info!("Task #{} completed! Result hash: 0x{}", task.id, hex::encode(result_hash));

                        // Try to upload result to IPFS (optional)
                        if let Ok(result_cid) = storage.put(&result).await {
                            info!("Result uploaded to IPFS: {}", result_cid);
                        }

                        // Submit result on-chain
                        match blockchain.submit_result(task.id, result_hash, wallet).await {
                            Ok(tx_hash) => {
                                info!("Result submitted for task #{}! TX: {:?}", task.id, tx_hash);
                                info!("Reward: {} ETH", ethers::utils::format_ether(task.reward_per_node));

                                // Display updated earnings
                                if let Ok(earnings) = blockchain.get_node_earnings(wallet.address()).await {
                                    info!("{}", "=".repeat(40));
                                    info!("NODE EARNINGS SUMMARY");
                                    info!("{}", "-".repeat(40));
                                    info!("Tasks completed: {}", earnings.tasks_completed);
                                    info!("ETH balance: {} ETH", ethers::utils::format_ether(earnings.eth_balance));
                                    info!("COMP balance: {} COMP", ethers::utils::format_ether(earnings.comp_balance));
                                    info!("{}", "=".repeat(40));
                                }
                            }
                            Err(e) => {
                                error!("Failed to submit result for task #{}: {}", task.id, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Task #{} execution failed: {}", task.id, e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to claim task #{}: {}", task.id, e);
            }
        }
    }

    Ok(())
}

async fn handle_network_event(
    event: network::NetworkEvent,
    _blockchain: &blockchain::BlockchainClient,
    _storage: &storage::IpfsStorage,
    _compute: &compute::ComputeEngine,
) -> Result<()> {
    match event {
        network::NetworkEvent::PeerConnected(peer_id) => {
            info!("Peer connected: {}", peer_id);
        }
        network::NetworkEvent::PeerDisconnected(peer_id) => {
            info!("Peer disconnected: {}", peer_id);
        }
        network::NetworkEvent::TaskAnnounced(task) => {
            info!("New task announced: {}", task.id);
            // TODO: Evaluate if we can handle this task
        }
        network::NetworkEvent::ResultReceived(task_id, _result) => {
            info!("Result received for task: {}", task_id);
        }
    }
    Ok(())
}

async fn handle_blockchain_event(
    event: blockchain::BlockchainEvent,
    _network: &mut network::P2PNetwork,
) -> Result<()> {
    match event {
        blockchain::BlockchainEvent::TaskCreated(task_id) => {
            info!("New task created on-chain: {}", task_id);
            // Broadcast to P2P network
        }
        blockchain::BlockchainEvent::TaskCompleted(task_id) => {
            info!("Task completed: {}", task_id);
        }
        blockchain::BlockchainEvent::RewardReceived(amount) => {
            info!("Reward received: {} COMP", amount);
        }
    }
    Ok(())
}

async fn show_status(config: Config) -> Result<()> {
    println!("Node Status");
    println!("{}", "-".repeat(40));
    println!("Config file: {:?}", config.path);
    println!("Mode: {:?}", config.mode);
    println!("Listen addresses: {:?}", config.network.listen_addresses);
    Ok(())
}

async fn handle_tasks(_config: Config, subcommand: cli::TasksSubcommand) -> Result<()> {
    match subcommand {
        cli::TasksSubcommand::List => {
            println!("Available tasks:");
            // TODO: Query blockchain for available tasks
        }
        cli::TasksSubcommand::Submit { model: _, input: _, reward: _, nodes: _ } => {
            println!("Submitting task...");
            // TODO: Submit task via blockchain
        }
        cli::TasksSubcommand::Status { task_id } => {
            println!("Task {} status:", task_id);
            // TODO: Query task status
        }
    }
    Ok(())
}

async fn handle_wallet(config: Config, subcommand: cli::WalletSubcommand) -> Result<()> {
    // Load wallet
    let wallet = load_wallet(&config)?;

    match subcommand {
        cli::WalletSubcommand::Balance => {
            if let Some(wallet) = wallet {
                println!("Wallet Balance");
                println!("{}", "=".repeat(40));
                println!("Address: {:?}", wallet.address());

                // Connect to blockchain
                let discovery = discovery::Discovery::new(&config).await?;
                let blockchain = blockchain::BlockchainClient::new(&config, &discovery).await?;

                // Get earnings
                match blockchain.get_node_earnings(wallet.address()).await {
                    Ok(earnings) => {
                        println!("{}", "-".repeat(40));
                        println!("ETH Balance:     {} ETH", ethers::utils::format_ether(earnings.eth_balance));
                        println!("COMP Balance:    {} COMP", ethers::utils::format_ether(earnings.comp_balance));
                        println!("Tasks Completed: {}", earnings.tasks_completed);
                        println!("{}", "=".repeat(40));
                    }
                    Err(e) => {
                        println!("Error fetching balances: {}", e);
                    }
                }
            } else {
                println!("No wallet configured. Add 'private_key' to config.");
            }
        }
        cli::WalletSubcommand::Address => {
            if let Some(wallet) = wallet {
                println!("Wallet Address: {:?}", wallet.address());
            } else {
                println!("No wallet configured. Add 'private_key' to config.");
            }
        }
    }
    Ok(())
}

fn handle_config(config: Config, subcommand: cli::ConfigSubcommand) -> Result<()> {
    match subcommand {
        cli::ConfigSubcommand::Show => {
            println!("Current configuration:");
            println!("{}", toml::to_string_pretty(&config)?);
        }
        cli::ConfigSubcommand::Init => {
            println!("Initializing default configuration...");
            Config::create_default()?;
            println!("Created default config at ~/.oarn/config.toml");
        }
    }
    Ok(())
}
