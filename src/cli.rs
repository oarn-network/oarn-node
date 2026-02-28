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

    /// Governance voting
    Governance {
        #[command(subcommand)]
        subcommand: GovernanceSubcommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum TasksSubcommand {
    /// List available tasks
    List {
        /// Show all tasks (including completed/expired)
        #[arg(short, long)]
        all: bool,

        /// Maximum number of tasks to show
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },

    /// Submit a new task
    Submit {
        /// Path to the model file (will be uploaded to IPFS) or IPFS CID (starting with Qm or bafy)
        #[arg(short, long)]
        model: String,

        /// Path to the input data file (will be uploaded to IPFS) or IPFS CID
        #[arg(short, long)]
        input: String,

        /// Reward per node in ETH (e.g., 0.001)
        #[arg(short, long)]
        reward: f64,

        /// Number of nodes required for consensus
        #[arg(short, long, default_value = "3")]
        nodes: u32,

        /// Deadline in hours from now (default: 24 hours)
        #[arg(short, long, default_value = "24")]
        deadline_hours: u64,

        /// Model requirements as JSON (e.g., '{"framework":"onnx","min_ram":"4GB"}')
        #[arg(long, default_value = "{}")]
        requirements: String,
    },

    /// Check task status
    Status {
        /// Task ID
        task_id: u64,
    },

    /// Show tasks submitted by your wallet
    Mine,

    /// Check consensus status for a task
    Consensus {
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

#[derive(Subcommand, Debug)]
pub enum GovernanceSubcommand {
    /// List all proposals
    List {
        /// Show only active proposals
        #[arg(short, long)]
        active: bool,

        /// Maximum number to show
        #[arg(short, long, default_value = "10")]
        limit: u32,
    },

    /// View proposal details
    View {
        /// Proposal ID
        proposal_id: String,
    },

    /// Vote on a proposal
    Vote {
        /// Proposal ID
        proposal_id: String,

        /// Vote choice: for, against, abstain
        #[arg(short, long)]
        choice: String,
    },

    /// Check your voting power
    Power,

    /// Delegate your voting power
    Delegate {
        /// Address to delegate to (or "self" to self-delegate)
        to: String,
    },

    /// Create a new proposal (requires GOV tokens)
    Propose {
        /// Proposal title
        #[arg(short, long)]
        title: String,

        /// Proposal description
        #[arg(short, long)]
        description: String,

        /// Target contract address
        #[arg(long)]
        target: String,

        /// Function calldata (hex)
        #[arg(long, default_value = "0x")]
        calldata: String,

        /// ETH value to send
        #[arg(long, default_value = "0")]
        value: f64,
    },
}
