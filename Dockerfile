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
FROM --platform=$BUILDPLATFORM rust:1.94-bookworm AS builder

# Build arguments for cross-compilation
ARG TARGETPLATFORM
ARG TARGETARCH
ARG BUILDPLATFORM

# Install minimal dependencies and cargo-zigbuild for cross-compilation
# cargo-zigbuild uses Zig as a linker, which provides hermetic musl support
# without needing external toolchain downloads
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    musl-tools \
    musl-dev \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Zig (architecture-aware) and cargo-zigbuild for reliable cross-compilation
RUN case "$BUILDPLATFORM" in \
        linux/amd64) ZIG_ARCH="x86_64" ;; \
        linux/arm64) ZIG_ARCH="aarch64" ;; \
        *) echo "Unsupported build platform: $BUILDPLATFORM" && exit 1 ;; \
    esac && \
    curl -L "https://ziglang.org/download/0.13.0/zig-linux-${ZIG_ARCH}-0.13.0.tar.xz" | tar -xJ -C /opt && \
    ln -s /opt/zig-linux-${ZIG_ARCH}-0.13.0/zig /usr/local/bin/zig && \
    cargo install cargo-zigbuild

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

# Build dependencies only (this layer is cached).
#
# `--all-features`, matching what CI builds and what the release workflow ships.
# A narrower list here was how this image came to be built with a feature that
# no longer exists (`slatedb-storage`, from a storage backend removed long ago):
# the flag silently drifted away from every other build in the repository, and
# an image built from a subset would in any case ship without Postgres, cloud
# warehouses, credential vending or request signing — most of what the
# documentation tells an operator to configure.
#
# `|| true` here only, because this layer builds against a dummy `src/` and its
# whole purpose is to warm the dependency cache. The real build below must fail
# the image if it fails.
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo zigbuild --release --target $RUST_TARGET --all-features 2>/dev/null || true

# Remove dummy source
RUN rm -rf src/

# Copy actual source
COPY src/ src/

# Touch to force rebuild
RUN touch src/main.rs src/lib.rs

# Build the actual binary
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo zigbuild --release --target $RUST_TARGET --all-features && \
    cp /build/target/$RUST_TARGET/release/rustberg /build/rustberg && \
    strip /build/rustberg 2>/dev/null || true

# The state directory, created here because the runtime image is distroless and
# has no shell to create one in. Owned by UID 65532, which is `nonroot`.
RUN mkdir -p /build/rustberg-data/data /build/rustberg-data/warehouse && \
    chown -R 65532:65532 /build/rustberg-data

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
LABEL org.opencontainers.image.documentation="https://hupe1980.github.io/rustberg/"

# Copy binary from builder
COPY --from=builder /build/rustberg /usr/local/bin/rustberg

# Environment defaults.
#
# `RUSTBERG_CATALOG_URL` is set because production mode — the default — refuses
# to start without an explicit catalog location, and an image whose only
# documented `docker run` exits immediately is not a quick start. The path is a
# declared volume, so a container started without `-v` still runs and simply
# loses its catalog when it is removed, which is the same bargain every other
# stateful image makes. Mount something over it for anything that has to
# survive, or point the variable at `postgres://…` for a replicated deployment.
ENV RUSTBERG_HOST=0.0.0.0
ENV RUSTBERG_PORT=8000
ENV RUSTBERG_INSECURE_HTTP=false
ENV RUSTBERG_CATALOG_URL=file:///var/lib/rustberg/data
ENV RUSTBERG_WAREHOUSE=/var/lib/rustberg/warehouse
ENV RUST_LOG=info

# Writable by UID 65532, the `nonroot` user the image runs as.
COPY --from=builder --chown=65532:65532 /build/rustberg-data /var/lib/rustberg
VOLUME ["/var/lib/rustberg"]

# Expose default port
EXPOSE 8000

# Run as non-root (distroless:nonroot uses UID 65532)
USER nonroot:nonroot

# The image is distroless, so the only thing that can probe it is the binary
# itself. `healthcheck` reads /ready, which reports whether the catalog store
# and the policy set are usable — not merely that the process is alive.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/rustberg", "healthcheck"]

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
ENV RUSTBERG_CATALOG_URL=file:///var/lib/rustberg/data
ENV RUSTBERG_WAREHOUSE=/var/lib/rustberg/warehouse
ENV RUST_LOG=debug

COPY --from=builder --chown=65532:65532 /build/rustberg-data /var/lib/rustberg
VOLUME ["/var/lib/rustberg"]

EXPOSE 8000

USER nonroot:nonroot

# The image is distroless, so the only thing that can probe it is the binary
# itself. `healthcheck` reads /ready, which reports whether the catalog store
# and the policy set are usable — not merely that the process is alive.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/rustberg", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/rustberg"]

# -----------------------------------------------------------------------------
# Default target is the minimal runtime
# -----------------------------------------------------------------------------
FROM runtime
