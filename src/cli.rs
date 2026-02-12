//! CLI argument parsing for OARN node

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// OARN Node - Decentralized AI Research Network
#[derive(Parser, Debug)]
#[command(name = "oarn-node")]
#[command(author = "OARN Network Contributors")]
#[command(version)]
#[command(about = "Run an OARN network node to participate in decentralized AI research")]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "~/.oarn/config.toml")]
    pub config: PathBuf,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the OARN node
    Start,

    /// Show node status
    Status,

    /// Manage tasks
    Tasks {
        #[command(subcommand)]
        subcommand: TasksSubcommand,
    },

    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        subcommand: WalletSubcommand,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        subcommand: ConfigSubcommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum TasksSubcommand {
    /// List available tasks
    List,

    /// Submit a new task
    Submit {
        /// IPFS CID of the model
        #[arg(short, long)]
        model: String,

        /// IPFS CID of the input data
        #[arg(short, long)]
        input: String,

        /// Reward per node (in COMP)
        #[arg(short, long)]
        reward: f64,

        /// Number of nodes required
        #[arg(short, long, default_value = "3")]
        nodes: u32,
    },

    /// Check task status
    Status {
        /// Task ID
        task_id: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum WalletSubcommand {
    /// Show token balances
    Balance,

    /// Show wallet address
    Address,
}

#[derive(Subcommand, Debug)]
pub enum ConfigSubcommand {
    /// Show current configuration
    Show,

    /// Initialize default configuration
    Init,
}
