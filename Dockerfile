# =============================================================================
# Rustberg Docker Image
# Multi-stage, multi-arch build for minimal, secure production image
# =============================================================================
# Build commands:
#   Single arch:  docker build -t rustberg .
#   Multi-arch:   docker buildx build --platform linux/amd64,linux/arm64 -t rustberg .
#   Debug:        docker build --target debug -t rustberg:debug .
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build (supports both amd64 and arm64)
# -----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM rust:1.83-bookworm AS builder

# Build arguments for cross-compilation
ARG TARGETPLATFORM
ARG TARGETARCH
ARG BUILDPLATFORM

# Install musl toolchain for static linking
# Note: No cmake/clang needed - Rustberg is 100% pure Rust!
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    musl-tools \
    musl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install cross-compilation tools for arm64 if building on amd64
RUN if [ "$TARGETARCH" = "arm64" ] && [ "$BUILDPLATFORM" = "linux/amd64" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            gcc-aarch64-linux-gnu \
            libc6-dev-arm64-cross \
        && rm -rf /var/lib/apt/lists/* \
        && mkdir -p ~/.cargo \
        && printf '[target.aarch64-unknown-linux-musl]\nlinker = "aarch64-linux-gnu-gcc"\n' >> ~/.cargo/config.toml; \
    fi

# Set up Rust target based on architecture
RUN case "$TARGETARCH" in \
        amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;; \
        arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    rustup target add $RUST_TARGET && \
    echo "$RUST_TARGET" > /tmp/rust-target

WORKDIR /build

# Copy Cargo files first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy source for dependency caching
RUN mkdir -p src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs && \
    echo 'pub fn dummy() {}' > src/lib.rs

# Build dependencies only (this layer is cached)
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo build --release --target $RUST_TARGET --features slatedb-storage,cli,tls 2>/dev/null || true

# Remove dummy source
RUN rm -rf src/

# Copy actual source
COPY src/ src/

# Touch to force rebuild
RUN touch src/main.rs src/lib.rs

# Build the actual binary
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo build --release --target $RUST_TARGET --features slatedb-storage,cli,tls && \
    cp /build/target/$RUST_TARGET/release/rustberg /build/rustberg && \
    strip /build/rustberg 2>/dev/null || true

# Verify binary
RUN ls -lh /build/rustberg && file /build/rustberg

# -----------------------------------------------------------------------------
# Stage 2: Minimal Runtime (distroless for maximum security)
# -----------------------------------------------------------------------------
# Google's distroless: minimal attack surface
# - No shell, no package manager, no unnecessary binaries
# - Only libc and ca-certificates
# - Significantly fewer CVEs than debian-slim or alpine
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# OCI Labels
LABEL org.opencontainers.image.title="Rustberg"
LABEL org.opencontainers.image.description="Production-grade Apache Iceberg REST Catalog - 100% Rust"
LABEL org.opencontainers.image.vendor="hupe1980"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/hupe1980/rustberg"
LABEL org.opencontainers.image.documentation="https://github.com/hupe1980/rustberg#readme"

# Copy binary from builder
COPY --from=builder /build/rustberg /usr/local/bin/rustberg

# Environment defaults
ENV RUSTBERG_HOST=0.0.0.0
ENV RUSTBERG_PORT=8000
ENV RUSTBERG_INSECURE_HTTP=false
ENV RUST_LOG=info

# Expose default port
EXPOSE 8000

# Run as non-root (distroless:nonroot uses UID 65532)
USER nonroot:nonroot

# Entrypoint
ENTRYPOINT ["/usr/local/bin/rustberg"]

# -----------------------------------------------------------------------------
# Stage 3: Debug variant (with shell for troubleshooting)
# Build with: docker build --target debug -t rustberg:debug .
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:debug-nonroot AS debug

LABEL org.opencontainers.image.title="Rustberg (Debug)"
LABEL org.opencontainers.image.description="Debug variant with busybox shell for troubleshooting"

COPY --from=builder /build/rustberg /usr/local/bin/rustberg

ENV RUSTBERG_HOST=0.0.0.0
ENV RUSTBERG_PORT=8000
ENV RUSTBERG_INSECURE_HTTP=false
ENV RUST_LOG=debug

EXPOSE 8000

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/rustberg"]

# -----------------------------------------------------------------------------
# Default target is the minimal runtime
# -----------------------------------------------------------------------------
FROM runtime
