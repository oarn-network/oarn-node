//! CLI argument parsing for OARN node

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Output format for CLI commands
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable text output (default)
    #[default]
    Text,
    /// JSON output for scripting and automation
    Json,
}

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

    /// Output format (text or json)
    #[arg(long, value_enum, default_value = "text", global = true)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the OARN node
    Start,

    /// Show node status
    Status,

    /// Show detailed version information
    Version,

    /// Check node health and connectivity
    Health,

    /// Show connected peers and network info
    Peers {
        /// Show detailed peer information
        #[arg(short, long)]
        detailed: bool,
    },

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

        /// Use TaskRegistryV2
        #[arg(long)]
        v2: bool,
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

        /// Use TaskRegistryV2 with multi-node consensus
        #[arg(long)]
        v2: bool,

        /// Consensus type for V2: majority (>50%), supermajority (>66%), unanimous (100%)
        #[arg(long, default_value = "majority")]
        consensus: String,
    },

    /// Manually claim a specific task
    Claim {
        /// Task ID to claim
        task_id: u64,

        /// Use TaskRegistryV2
        #[arg(long)]
        v2: bool,

        /// Also execute the task after claiming
        #[arg(short, long)]
        execute: bool,
    },

    /// Check task status
    Status {
        /// Task ID
        task_id: u64,

        /// Use TaskRegistryV2
        #[arg(long)]
        v2: bool,
    },

    /// Show tasks submitted by your wallet
    Mine {
        /// Use TaskRegistryV2
        #[arg(long)]
        v2: bool,
    },

    /// Check consensus status for a task (V2 only)
    Consensus {
        /// Task ID
        task_id: u64,
    },

    /// Cancel a task you submitted (before any node claims it)
    Cancel {
        /// Task ID to cancel
        task_id: u64,

        /// Use TaskRegistryV2
        #[arg(long)]
        v2: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum WalletSubcommand {
    /// Show token balances
    Balance,

    /// Show wallet address
    Address,

    /// Send ETH to another address
    Send {
        /// Recipient address
        to: String,

        /// Amount in ETH (e.g., 0.1)
        amount: f64,

        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Show recent transactions
    History {
        /// Number of transactions to show
        #[arg(short, long, default_value = "10")]
        limit: u32,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigSubcommand {
    /// Show current configuration
    Show,

    /// Initialize default configuration
    Init,

    /// Validate configuration file
    Validate,

    /// Show config file path
    Path,
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
