# OARN Node - Multi-stage Docker build
# Stage 1: Build
FROM rust:1.75-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy Cargo files first for dependency caching
COPY Cargo.toml Cargo.lock* ./

# Create dummy main.rs for dependency compilation
RUN mkdir -p src && echo "fn main() {}" > src/main.rs

# Build dependencies only (will be cached)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual application
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 oarn

# Create directories for config and data
RUN mkdir -p /home/oarn/.oarn /data && chown -R oarn:oarn /home/oarn /data

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/oarn-node /app/oarn-node

# Copy default config if exists
COPY --chown=oarn:oarn config.example.toml /home/oarn/.oarn/config.toml.example

# Switch to non-root user
USER oarn

# Default ports:
# - 4001: libp2p
# - 8080: HTTP API (if implemented)
EXPOSE 4001 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["/app/oarn-node"]
CMD ["start"]
