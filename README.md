# OARN Node

Rust implementation of the OARN network node software for participating in decentralized AI research.

## Features

- **P2P Networking**: libp2p-based peer discovery and messaging
- **Decentralized Discovery**: All infrastructure discovered via ENS/DHT (no hardcoded values)
- **Three Operational Modes**:
  - Local: Offline inference only
  - Standard: Full P2P network participation
  - Validator-Routed: High-speed mode via validator network
- **IPFS Integration**: Decentralized model and data storage
- **Privacy Features**: Optional Tor support, traffic padding, peer rotation

## Requirements

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- IPFS daemon (optional, for network mode)
- 8GB+ RAM recommended
- GPU optional (for accelerated inference)

## Installation

### From Source

```bash
# Clone repository
git clone https://github.com/oarn-network/oarn-node.git
cd oarn-node

# Build release binary
cargo build --release

# Binary will be at ./target/release/oarn-node
```

### Using Cargo

```bash
cargo install oarn-node
```

## Quick Start

```bash
# Initialize configuration
oarn-node config init

# Start the node
oarn-node start

# Check status
oarn-node status
```

## Configuration

Configuration file location: `~/.oarn/config.toml`

```toml
# Node operational mode
mode = "standard"  # local, standard, validator_routed, auto

[network]
listen_addresses = ["/ip4/0.0.0.0/tcp/4001"]
max_peers = 50

[network.discovery]
# IMPORTANT: No hardcoded bootstrap nodes!
# Discovery happens via ENS/DHT/on-chain registry
method = "auto"  # auto, ens, dht, manual
ens_registry = "oarn-registry.eth"

[blockchain]
chain_id = 421614  # Arbitrum Sepolia (testnet)
rpc_discovery = "registry"  # Use on-chain registry for RPC discovery

[storage]
ipfs_api = "http://127.0.0.1:5001"
cache_dir = "~/.oarn/cache"
max_cache_mb = 10240

[compute]
frameworks = ["onnx", "pytorch"]
concurrent_tasks = 1

[privacy]
tor_enabled = false
padding_enabled = true
rotate_peers = true
```

## CLI Commands

```bash
# Node operations
oarn-node start              # Start the node
oarn-node status             # Show node status

# Task management
oarn-node tasks list         # List available tasks
oarn-node tasks submit       # Submit a new task
oarn-node tasks status <id>  # Check task status

# Wallet operations
oarn-node wallet balance     # Show token balances
oarn-node wallet address     # Show wallet address

# Configuration
oarn-node config show        # Display current config
oarn-node config init        # Create default config
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     OARN Node                            │
├─────────────────────────────────────────────────────────┤
│  CLI (clap)                                             │
├─────────────────────────────────────────────────────────┤
│  Discovery    │  Network     │  Blockchain  │  Compute  │
│  (ENS/DHT)    │  (libp2p)    │  (ethers)    │  (ONNX)   │
├─────────────────────────────────────────────────────────┤
│  Storage (IPFS)              │  Config (TOML)           │
└─────────────────────────────────────────────────────────┘
```

## Security Principles

1. **Zero Hardcoded Values**: All infrastructure discovered dynamically
2. **End-to-End Encryption**: Noise protocol for P2P, HTTPS for RPC
3. **Optional Tor**: Full anonymity when needed
4. **Traffic Analysis Resistance**: Message padding, random delays
5. **Sandboxed Execution**: Model inference in isolated environment

## Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- start

# Check formatting
cargo fmt --check

# Run linter
cargo clippy

# Build documentation
cargo doc --open
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](./LICENSE)
