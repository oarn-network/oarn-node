# Contributing to OARN Node

Thank you for your interest in contributing to OARN!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/oarn-node.git`
3. Install Rust: https://rustup.rs/
4. Create a branch: `git checkout -b feature/your-feature`

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- start

# Check formatting
cargo fmt --check

# Run linter
cargo clippy
```

## Code Standards

- Follow Rust idioms and best practices
- Document public APIs with rustdoc comments
- Write unit tests for new functionality
- Handle errors properly (use `anyhow` for application errors)
- No `unwrap()` in production code (use `?` or explicit error handling)

## Architecture

```
src/
├── main.rs       # Entry point and CLI
├── cli.rs        # Command line interface
├── config.rs     # Configuration management
├── network.rs    # P2P networking (libp2p)
├── discovery.rs  # Infrastructure discovery
├── blockchain.rs # Ethereum integration
├── storage.rs    # IPFS integration
└── compute.rs    # AI inference engine
```

## Pull Request Process

1. Ensure `cargo test` passes
2. Ensure `cargo clippy` has no warnings
3. Ensure `cargo fmt` is applied
4. Update documentation if needed
5. Request review from maintainers

## Security Principles

- **No hardcoded values**: All infrastructure discovered via ENS/DHT
- **End-to-end encryption**: Use Noise protocol for P2P
- **Privacy by default**: Support Tor, traffic padding

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
