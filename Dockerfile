# Build stage
FROM rust:bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev \
    llvm clang libbpf-dev libelf-dev linux-libc-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm

# Cache dependencies before copying full source
COPY Cargo.toml Cargo.lock build.rs ./
COPY bpf/ bpf/
RUN mkdir -p src/bin src/cli src/mcp src/scanner src/timing \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > src/bin/server.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --bin limpet-server 2>/dev/null || true

COPY src/ src/
RUN touch src/main.rs src/bin/server.rs src/lib.rs \
    && cargo build --release --bin limpet-server

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/limpet-server /usr/local/bin/limpet-server

EXPOSE 8888
ENTRYPOINT ["limpet-server"]
