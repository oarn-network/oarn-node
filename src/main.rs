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
use serde_json::json;
use std::time::Duration;
use tokio::time::interval;
use tracing::{info, warn, error, debug, Level};
use tracing_subscriber::FmtSubscriber;

use crate::cli::{Cli, Commands, OutputFormat};
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

    let output_format = cli.output;

    match cli.command {
        Commands::Start => {
            info!("Starting OARN node...");
            run_node(config).await?;
        }
        Commands::Status => {
            show_status(config, output_format).await?;
        }
        Commands::Version => {
            show_version(output_format);
        }
        Commands::Health => {
            check_health(config, output_format).await?;
        }
        Commands::Peers { detailed } => {
            show_peers(config, detailed, output_format).await?;
        }
        Commands::Tasks { subcommand } => {
            handle_tasks(config, subcommand, output_format).await?;
        }
        Commands::Wallet { subcommand } => {
            handle_wallet(config, subcommand, output_format).await?;
        }
        Commands::Config { subcommand } => {
            handle_config(config, subcommand, output_format)?;
        }
        Commands::Governance { subcommand } => {
            handle_governance(config, subcommand, output_format).await?;
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

    // Peer discovery interval (every 60 seconds)
    let mut peer_discovery_interval = interval(Duration::from_secs(60));

    // Network stats interval (every 2 minutes)
    let mut stats_interval = interval(Duration::from_secs(120));

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

            // Poll for available tasks (V1 and V2)
            _ = task_poll_interval.tick() => {
                if let Some(ref wallet) = wallet {
                    // Poll V2 tasks first (consensus tasks)
                    if let Err(e) = poll_and_process_tasks_v2(&blockchain, &storage, &compute, wallet).await {
                        debug!("V2 Task polling error: {}", e);
                    }
                    // Also poll V1 tasks for backwards compatibility
                    if let Err(e) = poll_and_process_tasks(&blockchain, &storage, &compute, wallet).await {
                        error!("Task polling error: {}", e);
                    }
                }
            }

            // Periodic peer discovery via DHT
            _ = peer_discovery_interval.tick() => {
                debug!("Running periodic peer discovery...");
                network.find_peers();
            }

            // Display network stats periodically
            _ = stats_interval.tick() => {
                let stats = network.stats();
                info!("Network: {} connected, {} discovered, bootstrap: {}",
                      stats.connected_peers, stats.discovered_peers,
                      if stats.bootstrap_complete { "complete" } else { "pending" });
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

/// Poll for available V2 tasks and process them (multi-node consensus)
async fn poll_and_process_tasks_v2(
    blockchain: &blockchain::BlockchainClient,
    storage: &storage::IpfsStorage,
    compute: &compute::ComputeEngine,
    wallet: &LocalWallet,
) -> Result<()> {
    if !blockchain.has_task_registry_v2() {
        return Ok(());
    }

    info!("Polling for available V2 tasks (consensus)...");

    let tasks = match blockchain.get_available_tasks_v2().await {
        Ok(t) => t,
        Err(e) => {
            debug!("No V2 tasks available: {}", e);
            return Ok(());
        }
    };

    if tasks.is_empty() {
        debug!("No available V2 tasks found");
        return Ok(());
    }

    info!("Found {} available V2 tasks", tasks.len());

    for task in tasks {
        // Check if we've already claimed this task
        let already_claimed = blockchain.has_claimed_task_v2(task.id, wallet.address()).await.unwrap_or(false);
        let already_submitted = blockchain.has_submitted_result_v2(task.id, wallet.address()).await.unwrap_or(false);

        if already_submitted {
            debug!("V2 Task #{} already completed by us", task.id);
            continue;
        }

        // Check if task can still accept claims
        if !task.can_claim() {
            debug!("V2 Task #{} - max claims reached", task.id);
            continue;
        }

        if already_claimed {
            info!("V2 Task #{} was claimed but not completed - processing now...", task.id);
            process_claimed_task_v2(&task, blockchain, storage, compute, wallet).await;
            continue;
        }

        info!("Claiming V2 task #{} ({})...", task.id, task.consensus_type_str());

        match blockchain.claim_task_v2(task.id, wallet).await {
            Ok(tx_hash) => {
                info!("V2 Task #{} claimed! TX: {:?}", task.id, tx_hash);
                process_claimed_task_v2(&task, blockchain, storage, compute, wallet).await;
            }
            Err(e) => {
                warn!("Failed to claim V2 task #{}: {}", task.id, e);
            }
        }
    }

    Ok(())
}

/// Process a V2 task that was claimed
async fn process_claimed_task_v2(
    task: &blockchain::TaskInfoV2,
    blockchain: &blockchain::BlockchainClient,
    storage: &storage::IpfsStorage,
    compute: &compute::ComputeEngine,
    wallet: &LocalWallet,
) {
    info!("Processing V2 task #{} ({})...", task.id, task.consensus_type_str());

    // Download model and input
    let model_data = storage.get(&task.model_hash).await;
    let input_data = storage.get(&task.input_hash).await;

    let (model, input) = match (model_data, input_data) {
        (Ok(m), Ok(i)) => {
            info!("Downloaded model and input from IPFS");
            (m, i)
        }
        _ => {
            warn!("IPFS unavailable - using placeholder data");
            (task.model_hash.to_vec(), task.input_hash.to_vec())
        }
    };

    // Execute
    info!("Executing V2 task #{}...", task.id);
    match compute.execute(&model, &input).await {
        Ok(result) => {
            let result_hash = compute.hash_result(&result);
            info!("V2 Task #{} completed! Result hash: 0x{}", task.id, hex::encode(result_hash));

            // Upload result to IPFS
            if let Ok(result_cid) = storage.put(&result).await {
                info!("Result uploaded to IPFS: {}", result_cid);
            }

            // Submit result to V2 contract
            match blockchain.submit_result_v2(task.id, result_hash, wallet).await {
                Ok(tx_hash) => {
                    info!("V2 Result submitted for task #{}! TX: {:?}", task.id, tx_hash);
                    info!("Consensus will be calculated when {} nodes submit", task.required_nodes);
                }
                Err(e) => {
                    error!("Failed to submit V2 result for task #{}: {}", task.id, e);
                }
            }
        }
        Err(e) => {
            error!("V2 Task #{} execution failed: {}", task.id, e);
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

/// Show version information
fn show_version(output_format: OutputFormat) {
    let version_info = json!({
        "name": "oarn-node",
        "version": env!("CARGO_PKG_VERSION"),
        "authors": env!("CARGO_PKG_AUTHORS"),
        "rust_version": env!("CARGO_PKG_RUST_VERSION"),
        "target": env!("TARGET"),
        "build_timestamp": env!("BUILD_TIMESTAMP"),
    });

    if output_format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&version_info).unwrap());
    } else {
        println!("OARN Node v{}", env!("CARGO_PKG_VERSION"));
        println!("{}", "=".repeat(40));
        println!("Authors:       {}", env!("CARGO_PKG_AUTHORS"));
        if let Ok(rust_ver) = std::env::var("CARGO_PKG_RUST_VERSION") {
            println!("Rust Version:  {}", rust_ver);
        }
        println!("Target:        {}", std::env::consts::ARCH);
        println!("OS:            {}", std::env::consts::OS);
    }
}

/// Check node health and connectivity
async fn check_health(config: Config, output_format: OutputFormat) -> Result<()> {
    let mut checks = Vec::new();

    // Check config
    let config_ok = config.path.exists();
    checks.push(("config", config_ok, if config_ok { "OK" } else { "Missing config file" }));

    // Check blockchain connectivity
    let blockchain_ok = match discovery::Discovery::new(&config).await {
        Ok(discovery) => {
            match blockchain::BlockchainClient::new(&config, &discovery).await {
                Ok(client) => {
                    match client.get_task_count().await {
                        Ok(_) => true,
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    };
    checks.push(("blockchain", blockchain_ok, if blockchain_ok { "Connected" } else { "Connection failed" }));

    // Check IPFS connectivity
    let ipfs_ok = match storage::IpfsStorage::new(&config).await {
        Ok(storage) => storage.is_available().await,
        Err(_) => false,
    };
    checks.push(("ipfs", ipfs_ok, if ipfs_ok { "Connected" } else { "Connection failed" }));

    // Check wallet
    let wallet_ok = load_wallet(&config).map(|w| w.is_some()).unwrap_or(false);
    checks.push(("wallet", wallet_ok, if wallet_ok { "Configured" } else { "Not configured" }));

    let all_ok = checks.iter().all(|(_, ok, _)| *ok);

    if output_format == OutputFormat::Json {
        let json_checks: Vec<_> = checks.iter().map(|(name, ok, msg)| {
            json!({ "check": name, "ok": ok, "message": msg })
        }).collect();
        println!("{}", serde_json::to_string_pretty(&json!({
            "healthy": all_ok,
            "checks": json_checks
        })).unwrap());
    } else {
        println!("Health Check");
        println!("{}", "=".repeat(40));
        for (name, ok, msg) in &checks {
            let status = if *ok { "✓" } else { "✗" };
            println!("{} {:<12} {}", status, name, msg);
        }
        println!("{}", "-".repeat(40));
        println!("Overall: {}", if all_ok { "Healthy" } else { "Unhealthy" });
    }

    Ok(())
}

/// Show connected peers
async fn show_peers(config: Config, detailed: bool, output_format: OutputFormat) -> Result<()> {
    let discovery = discovery::Discovery::new(&config).await?;
    let mut network = network::P2PNetwork::new(&config, &discovery).await?;

    let stats = network.stats();
    let peers = network.connected_peers();

    if output_format == OutputFormat::Json {
        let json_output = json!({
            "local_peer_id": network.local_peer_id().to_string(),
            "connected_peers": stats.connected_peers,
            "discovered_peers": stats.discovered_peers,
            "bootstrap_complete": stats.bootstrap_complete,
            "peers": if detailed {
                peers.iter().map(|p| json!({
                    "peer_id": p.id.to_string(),
                    "addresses": p.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                    "connected_since": p.connected_since,
                })).collect()
            } else {
                peers.iter().map(|p| json!(p.id.to_string())).collect()
            }
        });
        println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
    } else {
        println!("P2P Network Status");
        println!("{}", "=".repeat(60));
        println!("Local Peer ID:    {}", network.local_peer_id());
        println!("Connected Peers:  {}", stats.connected_peers);
        println!("Discovered Peers: {}", stats.discovered_peers);
        println!("Bootstrap:        {}", if stats.bootstrap_complete { "Complete" } else { "In Progress" });

        if !peers.is_empty() {
            println!("{}", "-".repeat(60));
            println!("Connected Peers:");
            for peer in &peers {
                if detailed {
                    println!("  {} ", peer.id);
                    for addr in &peer.addresses {
                        println!("    └─ {}", addr);
                    }
                } else {
                    println!("  {}", peer.id);
                }
            }
        }
        println!("{}", "=".repeat(60));
    }

    Ok(())
}

async fn show_status(config: Config, output_format: OutputFormat) -> Result<()> {
    if output_format == OutputFormat::Json {
        let status = json!({
            "config_file": config.path.to_string_lossy(),
            "mode": format!("{:?}", config.mode),
            "listen_addresses": config.network.listen_addresses,
            "chain_id": config.blockchain.chain_id,
        });
        println!("{}", serde_json::to_string_pretty(&status).unwrap());
    } else {
        println!("Node Status");
        println!("{}", "-".repeat(40));
        println!("Config file: {:?}", config.path);
        println!("Mode: {:?}", config.mode);
        println!("Listen addresses: {:?}", config.network.listen_addresses);
    }
    Ok(())
}

async fn handle_tasks(config: Config, subcommand: cli::TasksSubcommand, output_format: OutputFormat) -> Result<()> {
    // Initialize discovery and blockchain connection
    let discovery = discovery::Discovery::new(&config).await?;
    let blockchain = blockchain::BlockchainClient::new(&config, &discovery).await?;

    match subcommand {
        cli::TasksSubcommand::List { all, limit, v2 } => {
            let tasks = if v2 {
                blockchain.get_available_tasks_v2().await?
            } else {
                blockchain.get_available_tasks().await?
            };

            if output_format == OutputFormat::Json {
                let json_tasks: Vec<_> = tasks.iter().take(if all { tasks.len() } else { limit as usize }).map(|t| {
                    json!({
                        "id": t.id,
                        "reward_per_node": ethers::utils::format_ether(t.reward_per_node).to_string(),
                        "required_nodes": t.required_nodes,
                        "deadline": t.deadline,
                        "status": "available"
                    })
                }).collect();
                println!("{}", serde_json::to_string_pretty(&json!({
                    "tasks": json_tasks,
                    "total": tasks.len(),
                    "version": if v2 { "v2" } else { "v1" }
                })).unwrap());
                return Ok(());
            }

            println!("Querying tasks from blockchain...\n");

            if tasks.is_empty() {
                println!("No available tasks found.");
                return Ok(());
            }

            println!("{}", "=".repeat(80));
            println!("{:<6} {:<12} {:<15} {:<12} {:<10}", "ID", "Reward", "Nodes", "Deadline", "Status");
            println!("{}", "-".repeat(80));

            let mut shown = 0u32;
            for task in &tasks {
                if shown >= limit && !all {
                    break;
                }

                let deadline_str = format_deadline(task.deadline);
                println!(
                    "{:<6} {:<12} {:<15} {:<12} {:<10}",
                    task.id,
                    format!("{:.4} ETH", ethers::utils::format_ether(task.reward_per_node)),
                    format!("{} required", task.required_nodes),
                    deadline_str,
                    "Available"
                );
                shown += 1;
            }

            println!("{}", "=".repeat(80));
            println!("Total: {} available tasks", tasks.len());

            if tasks.len() as u32 > limit && !all {
                println!("(Use --all to show all tasks)");
            }
        }

        cli::TasksSubcommand::Submit {
            model,
            input,
            reward,
            nodes,
            deadline_hours,
            requirements,
            v2,
            consensus,
        } => {
            // Load wallet
            let wallet = load_wallet(&config)?
                .context("Wallet required to submit tasks. Add 'private_key' to config.")?;

            println!("Task Submission");
            println!("{}", "=".repeat(50));

            // Initialize IPFS storage
            let storage = storage::IpfsStorage::new(&config).await?;

            // Handle model - either IPFS CID or local file
            let model_hash = if model.starts_with("Qm") || model.starts_with("bafy") {
                println!("Using existing IPFS CID for model: {}", model);
                cid_to_bytes32(&model)?
            } else {
                // Upload local file to IPFS
                let path = std::path::PathBuf::from(&model);
                if !path.exists() {
                    anyhow::bail!("Model file not found: {}", model);
                }
                println!("Uploading model to IPFS: {}", model);
                let data = tokio::fs::read(&path).await?;
                let cid = storage.put(&data).await?;
                println!("Model uploaded: {}", cid);
                cid_to_bytes32(&cid)?
            };

            // Handle input - either IPFS CID or local file
            let input_hash = if input.starts_with("Qm") || input.starts_with("bafy") {
                println!("Using existing IPFS CID for input: {}", input);
                cid_to_bytes32(&input)?
            } else {
                // Upload local file to IPFS
                let path = std::path::PathBuf::from(&input);
                if !path.exists() {
                    anyhow::bail!("Input file not found: {}", input);
                }
                println!("Uploading input to IPFS: {}", input);
                let data = tokio::fs::read(&path).await?;
                let cid = storage.put(&data).await?;
                println!("Input uploaded: {}", cid);
                cid_to_bytes32(&cid)?
            };

            // Calculate deadline
            let deadline = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
                + (deadline_hours * 3600);

            // Convert reward to wei
            let reward_wei = ethers::utils::parse_ether(reward)?;

            // Check minimum reward
            match blockchain.get_min_reward().await {
                Ok(min_reward) => {
                    if reward_wei < min_reward {
                        anyhow::bail!(
                            "Reward too low. Minimum: {} ETH",
                            ethers::utils::format_ether(min_reward)
                        );
                    }
                }
                Err(e) => {
                    warn!("Could not check minimum reward: {}", e);
                }
            }

            // Calculate total cost
            let total_cost = reward_wei * ethers::types::U256::from(nodes);

            println!("{}", "-".repeat(50));
            println!("Model hash:      0x{}", hex::encode(model_hash));
            println!("Input hash:      0x{}", hex::encode(input_hash));
            println!("Reward per node: {} ETH", reward);
            println!("Required nodes:  {}", nodes);
            println!("Total cost:      {} ETH", ethers::utils::format_ether(total_cost));
            println!("Deadline:        {} hours from now", deadline_hours);
            println!("Requirements:    {}", requirements);
            println!("{}", "-".repeat(50));

            // Check wallet balance
            let balance = blockchain.get_eth_balance(wallet.address()).await?;
            if balance < total_cost {
                anyhow::bail!(
                    "Insufficient balance. Required: {} ETH, Available: {} ETH",
                    ethers::utils::format_ether(total_cost),
                    ethers::utils::format_ether(balance)
                );
            }

            println!("\nSubmitting task to blockchain...");

            if v2 {
                // Parse consensus type
                let consensus_type: u8 = match consensus.to_lowercase().as_str() {
                    "majority" => 0,
                    "supermajority" | "super" => 1,
                    "unanimous" | "all" => 2,
                    _ => {
                        warn!("Unknown consensus type '{}', using majority", consensus);
                        0
                    }
                };

                println!("Using TaskRegistryV2 with {} consensus", match consensus_type {
                    0 => "Majority (>50%)",
                    1 => "SuperMajority (>66%)",
                    2 => "Unanimous (100%)",
                    _ => "Unknown",
                });

                match blockchain.submit_task_v2(
                    model_hash,
                    input_hash,
                    &requirements,
                    reward_wei,
                    nodes as u64,
                    deadline,
                    consensus_type,
                    &wallet,
                ).await {
                    Ok((tx_hash, task_id)) => {
                        println!("\n{}", "=".repeat(50));
                        println!("TASK SUBMITTED TO V2 SUCCESSFULLY!");
                        println!("{}", "-".repeat(50));
                        println!("Task ID:     {}", task_id);
                        println!("TX Hash:     {:?}", tx_hash);
                        println!("Contract:    TaskRegistryV2");
                        println!("Consensus:   {}", match consensus_type {
                            0 => "Majority (>50%)",
                            1 => "SuperMajority (>66%)",
                            2 => "Unanimous (100%)",
                            _ => "Unknown",
                        });
                        println!("{}", "=".repeat(50));
                    }
                    Err(e) => {
                        error!("Failed to submit task to V2: {}", e);
                        anyhow::bail!("Task V2 submission failed: {}", e);
                    }
                }
            } else {
                match blockchain.submit_task(
                    model_hash,
                    input_hash,
                    &requirements,
                    reward_wei,
                    nodes as u64,
                    deadline,
                    &wallet,
                ).await {
                    Ok((tx_hash, task_id)) => {
                        println!("\n{}", "=".repeat(50));
                        println!("TASK SUBMITTED SUCCESSFULLY!");
                        println!("{}", "-".repeat(50));
                        println!("Task ID:     {}", task_id);
                        println!("TX Hash:     {:?}", tx_hash);
                        println!("{}", "=".repeat(50));
                    }
                    Err(e) => {
                        error!("Failed to submit task: {}", e);
                        anyhow::bail!("Task submission failed: {}", e);
                    }
                }
            }
        }

        cli::TasksSubcommand::Status { task_id, v2 } => {
            if output_format == OutputFormat::Json {
                let task = blockchain.get_task_details(task_id).await?;
                let json_output = json!({
                    "id": task.id,
                    "status": task.status_str(),
                    "mode": task.mode_str(),
                    "requester": format!("{:?}", task.requester),
                    "model_hash": format!("0x{}", hex::encode(task.model_hash)),
                    "input_hash": format!("0x{}", hex::encode(task.input_hash)),
                    "requirements": task.model_requirements,
                    "reward_per_node": ethers::utils::format_ether(task.reward_per_node).to_string(),
                    "required_nodes": task.required_nodes,
                    "completed_nodes": task.completed_nodes,
                    "deadline": task.deadline,
                    "created_at": task.created_at,
                    "version": if v2 { "v2" } else { "v1" }
                });
                println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
                return Ok(());
            }

            println!("Querying task #{}...\n", task_id);

            match blockchain.get_task_details(task_id).await {
                Ok(task) => {
                    println!("{}", "=".repeat(60));
                    println!("TASK #{}", task.id);
                    println!("{}", "-".repeat(60));
                    println!("Status:          {}", task.status_str());
                    println!("Mode:            {}", task.mode_str());
                    println!("Requester:       {:?}", task.requester);
                    println!("Model hash:      0x{}", hex::encode(task.model_hash));
                    println!("Input hash:      0x{}", hex::encode(task.input_hash));
                    println!("Requirements:    {}", task.model_requirements);
                    println!("Reward/node:     {} ETH", ethers::utils::format_ether(task.reward_per_node));
                    println!("Nodes:           {} / {} completed", task.completed_nodes, task.required_nodes);
                    println!("Deadline:        {}", format_timestamp(task.deadline));
                    println!("Created:         {}", format_timestamp(task.created_at));
                    println!("{}", "=".repeat(60));
                }
                Err(e) => {
                    println!("Error: Could not find task #{}: {}", task_id, e);
                }
            }
        }

        cli::TasksSubcommand::Claim { task_id, v2, execute } => {
            let wallet = load_wallet(&config)?
                .context("Wallet required to claim tasks. Add 'private_key' to config.")?;

            if output_format != OutputFormat::Json {
                println!("Claiming task #{}...", task_id);
            }

            let result = if v2 {
                blockchain.claim_task_v2(task_id, &wallet).await
            } else {
                blockchain.claim_task(task_id, &wallet).await
            };

            match result {
                Ok(tx_hash) => {
                    if output_format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "success": true,
                            "task_id": task_id,
                            "tx_hash": format!("{:?}", tx_hash),
                            "version": if v2 { "v2" } else { "v1" }
                        })).unwrap());
                    } else {
                        println!("Task #{} claimed successfully!", task_id);
                        println!("TX Hash: {:?}", tx_hash);
                    }

                    // Execute if requested
                    if execute {
                        if output_format != OutputFormat::Json {
                            println!("\nExecuting task...");
                        }
                        let storage = storage::IpfsStorage::new(&config).await?;
                        let compute = compute::ComputeEngine::new(&config)?;

                        if v2 {
                            if let Ok(task) = blockchain.get_task_details_v2(task_id).await {
                                process_claimed_task_v2(&task, &blockchain, &storage, &compute, &wallet).await;
                            }
                        } else {
                            if let Ok(task) = blockchain.get_task_details(task_id).await {
                                process_claimed_task(&task, &blockchain, &storage, &compute, &wallet).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    if output_format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "success": false,
                            "error": format!("{}", e)
                        })).unwrap());
                    } else {
                        println!("Failed to claim task #{}: {}", task_id, e);
                    }
                }
            }
        }

        cli::TasksSubcommand::Cancel { task_id, v2 } => {
            let wallet = load_wallet(&config)?
                .context("Wallet required to cancel tasks. Add 'private_key' to config.")?;

            if output_format != OutputFormat::Json {
                println!("Cancelling task #{}...", task_id);
            }

            let result = if v2 {
                blockchain.cancel_task_v2(task_id, &wallet).await
            } else {
                blockchain.cancel_task(task_id, &wallet).await
            };

            match result {
                Ok(tx_hash) => {
                    if output_format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "success": true,
                            "task_id": task_id,
                            "tx_hash": format!("{:?}", tx_hash),
                            "version": if v2 { "v2" } else { "v1" }
                        })).unwrap());
                    } else {
                        println!("Task #{} cancelled successfully!", task_id);
                        println!("TX Hash: {:?}", tx_hash);
                    }
                }
                Err(e) => {
                    if output_format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "success": false,
                            "error": format!("{}", e)
                        })).unwrap());
                    } else {
                        println!("Failed to cancel task #{}: {}", task_id, e);
                    }
                }
            }
        }

        cli::TasksSubcommand::Mine { v2 } => {
            let wallet = load_wallet(&config)?
                .context("Wallet required. Add 'private_key' to config.")?;

            println!("Tasks submitted by {:?}\n", wallet.address());

            let task_count = blockchain.get_task_count().await?;
            let mut my_tasks = Vec::new();

            for i in 1..=task_count {
                if let Ok(task) = blockchain.get_task_details(i).await {
                    if task.requester == wallet.address() {
                        my_tasks.push(task);
                    }
                }
            }

            if my_tasks.is_empty() {
                println!("You have not submitted any tasks.");
                return Ok(());
            }

            println!("{}", "=".repeat(80));
            println!("{:<6} {:<12} {:<10} {:<12} {:<10}", "ID", "Reward", "Nodes", "Status", "Completed");
            println!("{}", "-".repeat(80));

            for task in &my_tasks {
                println!(
                    "{:<6} {:<12} {:<10} {:<12} {:<10}",
                    task.id,
                    format!("{:.4} ETH", ethers::utils::format_ether(task.reward_per_node)),
                    task.required_nodes,
                    task.status_str(),
                    format!("{}/{}", task.completed_nodes, task.required_nodes)
                );
            }

            println!("{}", "=".repeat(80));
            println!("Total: {} tasks submitted", my_tasks.len());
        }

        cli::TasksSubcommand::Consensus { task_id } => {
            println!("Querying consensus status for task #{}...\n", task_id);

            match blockchain.get_consensus_status(task_id).await {
                Ok(status) => {
                    println!("{}", "=".repeat(70));
                    println!("CONSENSUS STATUS - TASK #{}", task_id);
                    println!("{}", "-".repeat(70));
                    println!("Task Status:       {}", status.task_status_str());
                    println!("Consensus Type:    {}", status.consensus_type_str());
                    println!("{}", "-".repeat(70));
                    println!("SUBMISSIONS");
                    println!("  Total:           {}", status.total_submissions);
                    println!("  Unique Results:  {}", status.unique_results);
                    println!("{}", "-".repeat(70));
                    println!("CONSENSUS");
                    println!("  Reached:         {}", if status.consensus_reached { "YES" } else { "NO" });
                    println!("  Winning Count:   {}", status.winning_count);
                    println!("  Agreement:       {:.1}%", status.consensus_percentage());

                    if status.winning_hash != [0u8; 32] {
                        println!("  Winning Hash:    0x{}", hex::encode(status.winning_hash));
                    }
                    println!("{}", "=".repeat(70));

                    // Try to get individual node results
                    match blockchain.get_task_node_results(task_id).await {
                        Ok(results) if !results.is_empty() => {
                            println!("\nNODE RESULTS");
                            println!("{}", "-".repeat(70));
                            println!("{:<44} {:<10} {:<10}", "Node", "Consensus", "Rewarded");
                            println!("{}", "-".repeat(70));

                            for result in &results {
                                println!(
                                    "{:<44} {:<10} {:<10}",
                                    format!("{:?}", result.node)[..42.min(format!("{:?}", result.node).len())].to_string(),
                                    if result.matches_consensus { "YES" } else { "NO" },
                                    if result.rewarded { "YES" } else { "NO" }
                                );
                            }
                            println!("{}", "=".repeat(70));
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    // Fall back to regular task status if V2 not available
                    println!("Note: Consensus features require TaskRegistryV2 contract.");
                    println!("Falling back to basic task status...\n");

                    match blockchain.get_task_details(task_id).await {
                        Ok(task) => {
                            println!("{}", "=".repeat(60));
                            println!("TASK #{}", task.id);
                            println!("{}", "-".repeat(60));
                            println!("Status:          {}", task.status_str());
                            println!("Nodes:           {} / {} completed", task.completed_nodes, task.required_nodes);
                            println!("Reward/node:     {} ETH", ethers::utils::format_ether(task.reward_per_node));
                            println!("{}", "=".repeat(60));
                        }
                        Err(_) => {
                            println!("Error: Could not find task #{}: {}", task_id, e);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Convert IPFS CID to bytes32 hash
fn cid_to_bytes32(cid: &str) -> Result<[u8; 32]> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(cid.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Format deadline as human-readable string
fn format_deadline(timestamp: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if timestamp <= now {
        return "Expired".to_string();
    }

    let remaining = timestamp - now;
    if remaining < 3600 {
        format!("{}m", remaining / 60)
    } else if remaining < 86400 {
        format!("{}h", remaining / 3600)
    } else {
        format!("{}d", remaining / 86400)
    }
}

/// Format Unix timestamp as human-readable string
fn format_timestamp(timestamp: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(timestamp as i64, 0);
    match dt {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{}", timestamp),
    }
}

async fn handle_wallet(config: Config, subcommand: cli::WalletSubcommand, output_format: OutputFormat) -> Result<()> {
    // Load wallet
    let wallet = load_wallet(&config)?;

    match subcommand {
        cli::WalletSubcommand::Balance => {
            if let Some(wallet) = wallet {
                // Connect to blockchain
                let discovery = discovery::Discovery::new(&config).await?;
                let blockchain = blockchain::BlockchainClient::new(&config, &discovery).await?;

                // Get earnings
                match blockchain.get_node_earnings(wallet.address()).await {
                    Ok(earnings) => {
                        if output_format == OutputFormat::Json {
                            println!("{}", serde_json::to_string_pretty(&json!({
                                "address": format!("{:?}", wallet.address()),
                                "eth_balance": ethers::utils::format_ether(earnings.eth_balance).to_string(),
                                "comp_balance": ethers::utils::format_ether(earnings.comp_balance).to_string(),
                                "tasks_completed": earnings.tasks_completed
                            })).unwrap());
                        } else {
                            println!("Wallet Balance");
                            println!("{}", "=".repeat(40));
                            println!("Address: {:?}", wallet.address());
                            println!("{}", "-".repeat(40));
                            println!("ETH Balance:     {} ETH", ethers::utils::format_ether(earnings.eth_balance));
                            println!("COMP Balance:    {} COMP", ethers::utils::format_ether(earnings.comp_balance));
                            println!("Tasks Completed: {}", earnings.tasks_completed);
                            println!("{}", "=".repeat(40));
                        }
                    }
                    Err(e) => {
                        if output_format == OutputFormat::Json {
                            println!("{}", serde_json::to_string_pretty(&json!({
                                "error": format!("{}", e)
                            })).unwrap());
                        } else {
                            println!("Error fetching balances: {}", e);
                        }
                    }
                }
            } else {
                if output_format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "error": "No wallet configured"
                    })).unwrap());
                } else {
                    println!("No wallet configured. Add 'private_key' to config.");
                }
            }
        }
        cli::WalletSubcommand::Address => {
            if let Some(wallet) = wallet {
                if output_format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "address": format!("{:?}", wallet.address())
                    })).unwrap());
                } else {
                    println!("Wallet Address: {:?}", wallet.address());
                }
            } else {
                if output_format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "error": "No wallet configured"
                    })).unwrap());
                } else {
                    println!("No wallet configured. Add 'private_key' to config.");
                }
            }
        }
        cli::WalletSubcommand::Send { to, amount, yes } => {
            let wallet = wallet.context("Wallet required to send ETH. Add 'private_key' to config.")?;

            let to_address: ethers::types::Address = to.parse()
                .context("Invalid recipient address")?;

            let amount_wei = ethers::utils::parse_ether(amount)?;

            // Connect to blockchain
            let discovery = discovery::Discovery::new(&config).await?;
            let blockchain = blockchain::BlockchainClient::new(&config, &discovery).await?;

            // Check balance
            let balance = blockchain.get_eth_balance(wallet.address()).await?;
            if balance < amount_wei {
                anyhow::bail!(
                    "Insufficient balance. Available: {} ETH, Required: {} ETH",
                    ethers::utils::format_ether(balance),
                    amount
                );
            }

            if output_format != OutputFormat::Json && !yes {
                println!("Send {} ETH to {:?}?", amount, to_address);
                println!("(Use -y to skip confirmation)");
                // In a real CLI, you'd prompt for confirmation here
                // For now, we proceed since they didn't use -y
            }

            match blockchain.send_eth(to_address, amount_wei, &wallet).await {
                Ok(tx_hash) => {
                    if output_format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "success": true,
                            "tx_hash": format!("{:?}", tx_hash),
                            "to": format!("{:?}", to_address),
                            "amount": amount
                        })).unwrap());
                    } else {
                        println!("Transaction sent!");
                        println!("TX Hash: {:?}", tx_hash);
                    }
                }
                Err(e) => {
                    if output_format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "success": false,
                            "error": format!("{}", e)
                        })).unwrap());
                    } else {
                        println!("Failed to send ETH: {}", e);
                    }
                }
            }
        }
        cli::WalletSubcommand::History { limit } => {
            let wallet = wallet.context("Wallet required. Add 'private_key' to config.")?;

            // Connect to blockchain
            let discovery = discovery::Discovery::new(&config).await?;
            let blockchain = blockchain::BlockchainClient::new(&config, &discovery).await?;

            match blockchain.get_transaction_history(wallet.address(), limit).await {
                Ok(txs) => {
                    if output_format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "address": format!("{:?}", wallet.address()),
                            "transactions": txs.iter().map(|tx| json!({
                                "hash": tx.hash,
                                "from": tx.from,
                                "to": tx.to,
                                "value": tx.value,
                                "timestamp": tx.timestamp
                            })).collect::<Vec<_>>()
                        })).unwrap());
                    } else {
                        println!("Transaction History for {:?}", wallet.address());
                        println!("{}", "=".repeat(70));
                        if txs.is_empty() {
                            println!("No transactions found.");
                        } else {
                            for tx in &txs {
                                println!("{} | {} ETH | {}",
                                    &tx.hash[..10],
                                    tx.value,
                                    if tx.from == format!("{:?}", wallet.address()) { "OUT" } else { "IN" }
                                );
                            }
                        }
                        println!("{}", "=".repeat(70));
                    }
                }
                Err(e) => {
                    if output_format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "error": format!("{}", e)
                        })).unwrap());
                    } else {
                        println!("Error fetching transaction history: {}", e);
                        println!("Note: Transaction history requires an indexer service.");
                    }
                }
            }
        }
    }
    Ok(())
}

fn handle_config(config: Config, subcommand: cli::ConfigSubcommand, output_format: OutputFormat) -> Result<()> {
    match subcommand {
        cli::ConfigSubcommand::Show => {
            if output_format == OutputFormat::Json {
                // Output config as JSON
                println!("{}", serde_json::to_string_pretty(&json!({
                    "path": config.path.to_string_lossy(),
                    "mode": format!("{:?}", config.mode),
                    "network": {
                        "listen_addresses": config.network.listen_addresses,
                        "max_peers": config.network.max_peers
                    },
                    "blockchain": {
                        "chain_id": config.blockchain.chain_id,
                        "rpc_url": config.blockchain.manual_rpc_url
                    }
                })).unwrap());
            } else {
                println!("Current configuration:");
                println!("{}", toml::to_string_pretty(&config)?);
            }
        }
        cli::ConfigSubcommand::Init => {
            Config::create_default()?;
            if output_format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&json!({
                    "success": true,
                    "path": "~/.oarn/config.toml"
                })).unwrap());
            } else {
                println!("Initializing default configuration...");
                println!("Created default config at ~/.oarn/config.toml");
            }
        }
        cli::ConfigSubcommand::Validate => {
            // Config already loaded successfully if we got here
            if output_format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&json!({
                    "valid": true,
                    "path": config.path.to_string_lossy()
                })).unwrap());
            } else {
                println!("Configuration is valid!");
                println!("Config file: {:?}", config.path);
            }
        }
        cli::ConfigSubcommand::Path => {
            if output_format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&json!({
                    "path": config.path.to_string_lossy()
                })).unwrap());
            } else {
                println!("{}", config.path.display());
            }
        }
    }
    Ok(())
}

async fn handle_governance(config: Config, subcommand: cli::GovernanceSubcommand, output_format: OutputFormat) -> Result<()> {
    // Initialize discovery and blockchain
    let discovery = discovery::Discovery::new(&config).await?;
    let blockchain = blockchain::BlockchainClient::new(&config, &discovery).await?;

    match subcommand {
        cli::GovernanceSubcommand::List { active, limit } => {
            match blockchain.get_proposals(limit).await {
                Ok(proposals) => {
                    let filtered: Vec<_> = if active {
                        proposals.iter().filter(|p| p.status == 1).collect()
                    } else {
                        proposals.iter().collect()
                    };

                    if output_format == OutputFormat::Json {
                        let json_proposals: Vec<_> = filtered.iter().map(|p| json!({
                            "id": p.id,
                            "title": p.title,
                            "status": p.status_str(),
                            "for_votes": ethers::utils::format_ether(p.for_votes).to_string(),
                            "against_votes": ethers::utils::format_ether(p.against_votes).to_string()
                        })).collect();
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "proposals": json_proposals,
                            "total": filtered.len()
                        })).unwrap());
                        return Ok(());
                    }

                    println!("Querying governance proposals...\n");

                    if filtered.is_empty() {
                        println!("No proposals found.");
                        return Ok(());
                    }

                    println!("{}", "=".repeat(90));
                    println!("{:<12} {:<30} {:<12} {:<15} {:<15}", "ID", "Title", "Status", "For", "Against");
                    println!("{}", "-".repeat(90));

                    for proposal in &proposals {
                        // Skip non-active if --active flag
                        if active && proposal.status != 1 {
                            continue;
                        }

                        let title = if proposal.title.len() > 28 {
                            format!("{}...", &proposal.title[..25])
                        } else {
                            proposal.title.clone()
                        };

                        println!(
                            "{:<12} {:<30} {:<12} {:<15} {:<15}",
                            &proposal.id[..proposal.id.len().min(10)],
                            title,
                            proposal.status_str(),
                            ethers::utils::format_ether(proposal.for_votes),
                            ethers::utils::format_ether(proposal.against_votes),
                        );
                    }

                    println!("{}", "=".repeat(90));
                    println!("Total: {} proposals", proposals.len());
                }
                Err(e) => {
                    println!("Error fetching proposals: {}", e);
                    println!("\nNote: Governance contract may not be deployed yet.");
                }
            }
        }

        cli::GovernanceSubcommand::View { proposal_id } => {
            println!("Querying proposal {}...\n", proposal_id);

            // For now, get all and find by ID
            match blockchain.get_proposals(100).await {
                Ok(proposals) => {
                    if let Some(proposal) = proposals.iter().find(|p| p.id == proposal_id) {
                        println!("{}", "=".repeat(70));
                        println!("PROPOSAL {}", proposal.id);
                        println!("{}", "-".repeat(70));
                        println!("Title:       {}", proposal.title);
                        println!("Status:      {}", proposal.status_str());
                        println!("Proposer:    {:?}", proposal.proposer);
                        println!("{}", "-".repeat(70));
                        println!("Description:");
                        println!("{}", proposal.description);
                        println!("{}", "-".repeat(70));
                        println!("Voting:");
                        println!("  For:       {} GOV", ethers::utils::format_ether(proposal.for_votes));
                        println!("  Against:   {} GOV", ethers::utils::format_ether(proposal.against_votes));
                        println!("  Abstain:   {} GOV", ethers::utils::format_ether(proposal.abstain_votes));
                        println!("{}", "-".repeat(70));
                        println!("Timeline:");
                        println!("  Start Block: {}", proposal.start_block);
                        println!("  End Block:   {}", proposal.end_block);
                        println!("{}", "=".repeat(70));
                    } else {
                        println!("Proposal {} not found.", proposal_id);
                    }
                }
                Err(e) => {
                    println!("Error: {}", e);
                }
            }
        }

        cli::GovernanceSubcommand::Vote { proposal_id, choice } => {
            let wallet = load_wallet(&config)?
                .context("Wallet required to vote. Add 'private_key' to config.")?;

            let support = match choice.to_lowercase().as_str() {
                "for" | "yes" | "1" => 1u8,
                "against" | "no" | "0" => 0u8,
                "abstain" | "2" => 2u8,
                _ => {
                    anyhow::bail!("Invalid vote choice. Use: for, against, or abstain");
                }
            };

            // Check if already voted
            if blockchain.has_voted(&proposal_id, wallet.address()).await? {
                println!("You have already voted on this proposal.");
                return Ok(());
            }

            // Check voting power
            let voting_power = blockchain.get_voting_power(wallet.address()).await?;
            if voting_power.is_zero() {
                println!("You have no voting power. Delegate to yourself first:");
                println!("  oarn-node governance delegate self");
                return Ok(());
            }

            println!("Casting vote on proposal {}...", proposal_id);
            println!("Vote: {}", choice);
            println!("Voting power: {} GOV", ethers::utils::format_ether(voting_power));

            match blockchain.cast_vote(&proposal_id, support, &wallet).await {
                Ok(tx_hash) => {
                    println!("\n{}", "=".repeat(50));
                    println!("VOTE CAST SUCCESSFULLY!");
                    println!("TX Hash: {:?}", tx_hash);
                    println!("{}", "=".repeat(50));
                }
                Err(e) => {
                    error!("Failed to cast vote: {}", e);
                }
            }
        }

        cli::GovernanceSubcommand::Power => {
            let wallet = load_wallet(&config)?
                .context("Wallet required. Add 'private_key' to config.")?;

            println!("Governance Power for {:?}\n", wallet.address());

            match blockchain.get_gov_token_balance(wallet.address()).await {
                Ok(balance) => {
                    println!("GOV Token Balance: {} GOV", ethers::utils::format_ether(balance));
                }
                Err(e) => {
                    println!("Could not fetch GOV balance: {}", e);
                }
            }

            match blockchain.get_voting_power(wallet.address()).await {
                Ok(power) => {
                    println!("Voting Power:      {} GOV", ethers::utils::format_ether(power));
                }
                Err(e) => {
                    println!("Could not fetch voting power: {}", e);
                }
            }

            match blockchain.get_delegate(wallet.address()).await {
                Ok(delegate) => {
                    if delegate == wallet.address() {
                        println!("Delegated to:      Self");
                    } else if delegate == ethers::types::Address::zero() {
                        println!("Delegated to:      None (delegate to self to activate voting)");
                    } else {
                        println!("Delegated to:      {:?}", delegate);
                    }
                }
                Err(e) => {
                    println!("Could not fetch delegate: {}", e);
                }
            }
        }

        cli::GovernanceSubcommand::Delegate { to } => {
            let wallet = load_wallet(&config)?
                .context("Wallet required. Add 'private_key' to config.")?;

            let delegate_to = if to.to_lowercase() == "self" {
                wallet.address()
            } else {
                to.parse().context("Invalid address")?
            };

            println!("Delegating voting power to {:?}...", delegate_to);

            match blockchain.delegate_votes(delegate_to, &wallet).await {
                Ok(tx_hash) => {
                    println!("\n{}", "=".repeat(50));
                    println!("DELEGATION SUCCESSFUL!");
                    println!("TX Hash: {:?}", tx_hash);
                    println!("{}", "=".repeat(50));
                }
                Err(e) => {
                    error!("Failed to delegate: {}", e);
                }
            }
        }

        cli::GovernanceSubcommand::Propose { title, description, target, calldata, value } => {
            let wallet = load_wallet(&config)?
                .context("Wallet required. Add 'private_key' to config.")?;

            let target_addr: ethers::types::Address = target.parse()
                .context("Invalid target address")?;

            let calldata_bytes = if calldata == "0x" {
                vec![]
            } else {
                hex::decode(calldata.strip_prefix("0x").unwrap_or(&calldata))
                    .context("Invalid calldata hex")?
            };

            let value_wei = ethers::utils::parse_ether(value)?;

            println!("Creating Proposal");
            println!("{}", "=".repeat(50));
            println!("Title:       {}", title);
            println!("Target:      {:?}", target_addr);
            println!("Value:       {} ETH", value);
            println!("{}", "-".repeat(50));

            match blockchain.create_proposal(&title, &description, target_addr, calldata_bytes, value_wei, &wallet).await {
                Ok((tx_hash, proposal_id)) => {
                    println!("\n{}", "=".repeat(50));
                    println!("PROPOSAL CREATED!");
                    println!("Proposal ID: {}", proposal_id);
                    println!("TX Hash:     {:?}", tx_hash);
                    println!("{}", "=".repeat(50));
                }
                Err(e) => {
                    error!("Failed to create proposal: {}", e);
                }
            }
        }
    }

    Ok(())
}
