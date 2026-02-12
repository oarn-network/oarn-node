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

use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
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

    info!("Node started successfully!");
    info!("Listening on: {:?}", config.network.listen_addresses);
    info!("{}", "-".repeat(50));

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

            // Graceful shutdown on Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
                break;
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

async fn handle_wallet(_config: Config, subcommand: cli::WalletSubcommand) -> Result<()> {
    match subcommand {
        cli::WalletSubcommand::Balance => {
            println!("Wallet balance:");
            // TODO: Query token balances
        }
        cli::WalletSubcommand::Address => {
            println!("Wallet address:");
            // TODO: Show wallet address
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
