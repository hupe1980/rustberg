# Rustberg - Apache Iceberg REST Catalog
# https://github.com/hupe1980/rustberg
#
# Run `just --list` to see all available recipes

# Default recipe - show help
default:
    @just --list

# ============================================================================
# Development
# ============================================================================

# Build in debug mode
build:
    cargo build --all-features

# Build in release mode
build-release:
    cargo build --release --all-features

# Run the catalog server (development mode)
run *ARGS:
    cargo run --all-features -- {{ARGS}}

# Run with hot reload (requires cargo-watch)
watch:
    cargo watch -x 'run --all-features'

# Clean build artifacts
clean:
    cargo clean

# ============================================================================
# Testing
# ============================================================================

# Run all tests
test:
    cargo test --all-features

# Run tests with output
test-verbose:
    cargo test --all-features -- --nocapture

# Run unit tests only
test-unit:
    cargo test --lib --all-features

# Run integration tests only
test-integration:
    cargo test --test '*' --all-features

# Run doc tests only
test-doc:
    cargo test --doc --all-features

# Run tests with coverage (requires cargo-llvm-cov)
coverage:
    cargo llvm-cov --all-features --html
    @echo "Coverage report: target/llvm-cov/html/index.html"

# Run ignored tests (requires Docker)
test-ignored:
    cargo test --all-features -- --ignored

# Run Trino integration tests
test-trino:
    cargo test --test trino_integration_tests --all-features -- --ignored --nocapture

# Run Vault KMS tests
test-vault:
    cargo test --test vault_kms_tests --all-features -- --ignored --nocapture

# Run AWS KMS tests (requires LocalStack)
test-aws-kms:
    cargo test --test aws_kms_tests --all-features -- --ignored --nocapture

# ============================================================================
# Code Quality
# ============================================================================

# Run clippy linter
lint:
    cargo clippy --all-features -- -D warnings

# Run clippy with fixes
lint-fix:
    cargo clippy --all-features --fix --allow-dirty

# Format code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Run all checks (CI simulation)
check: fmt-check lint test test-doc
    @echo "✅ All checks passed!"

# Security audit
audit:
    cargo audit

# Check for outdated dependencies
outdated:
    cargo outdated

# Deny check (licenses, vulnerabilities)
deny:
    cargo deny check

# ============================================================================
# Documentation
# ============================================================================

# Build documentation
doc:
    cargo doc --all-features --no-deps --open

# Serve docs site locally (requires Ruby 3.0+)
docs-serve:
    #!/usr/bin/env bash
    set -eo pipefail
    
    # Try to use chruby if available
    if [[ -f /opt/homebrew/opt/chruby/share/chruby/chruby.sh ]]; then
        source /opt/homebrew/opt/chruby/share/chruby/chruby.sh
        chruby ruby-3.4.1 2>/dev/null || chruby ruby-3 2>/dev/null || true
    fi
    
    RUBY_VERSION=$(ruby -e 'puts RUBY_VERSION.split(".")[0..1].join(".")')
    if [[ $(echo "$RUBY_VERSION < 3.0" | bc -l) -eq 1 ]]; then
        echo "❌ Ruby 3.0+ required. Found: $(ruby -v)"
        echo ""
        echo "Install Ruby 3.0+ using one of:"
        echo "  brew install ruby           # Homebrew (macOS)"
        echo "  rbenv install 3.3.0         # rbenv"
        echo "  asdf install ruby 3.3.0     # asdf"
        echo ""
        echo "After installing, ensure the new Ruby is in your PATH."
        exit 1
    fi
    # Note: Sass deprecation warnings from Just the Docs theme are expected (upstream issue #1607)
    cd docs && bundle install && bundle exec jekyll serve --config _config.yml,_config_local.yml

# Build docs site (requires Ruby 3.0+)
docs-build:
    #!/usr/bin/env bash
    set -euo pipefail
    # Note: Sass deprecation warnings from Just the Docs theme are expected (upstream issue #1607)
    cd docs && bundle install && bundle exec jekyll build

# ============================================================================
# Release
# ============================================================================

# Create a release build for current platform
release:
    cargo build --release --all-features
    @echo "Binary: target/release/rustberg"
    @ls -lh target/release/rustberg

# Build release for all platforms (requires cross)
release-all:
    @echo "Building for Linux x86_64..."
    cross build --release --all-features --target x86_64-unknown-linux-gnu
    @echo "Building for Linux ARM64..."
    cross build --release --all-features --target aarch64-unknown-linux-gnu
    @echo "Building for macOS x86_64..."
    cross build --release --all-features --target x86_64-apple-darwin
    @echo "Building for macOS ARM64..."
    cross build --release --all-features --target aarch64-apple-darwin
    @echo "Building for Windows..."
    cross build --release --all-features --target x86_64-pc-windows-msvc

# Build Docker image
docker-build tag="latest":
    docker build -t rustberg:{{tag}} .

# Push Docker image
docker-push tag="latest" registry="ghcr.io/hupe1980":
    docker tag rustberg:{{tag}} {{registry}}/rustberg:{{tag}}
    docker push {{registry}}/rustberg:{{tag}}

# ============================================================================
# Kubernetes / Helm
# ============================================================================

# Lint Helm chart
helm-lint:
    helm lint charts/rustberg

# Template Helm chart (dry-run)
helm-template:
    helm template rustberg charts/rustberg

# Install Helm chart locally
helm-install namespace="default":
    helm install rustberg charts/rustberg -n {{namespace}}

# Upgrade Helm chart
helm-upgrade namespace="default":
    helm upgrade rustberg charts/rustberg -n {{namespace}}

# Uninstall Helm chart
helm-uninstall namespace="default":
    helm uninstall rustberg -n {{namespace}}

# Package Helm chart
helm-package:
    helm package charts/rustberg

# ============================================================================
# Development Utilities
# ============================================================================

# Start a local MinIO for S3 testing
minio:
    docker run -d --name minio \
        -p 9000:9000 -p 9001:9001 \
        -e MINIO_ROOT_USER=minioadmin \
        -e MINIO_ROOT_PASSWORD=minioadmin \
        minio/minio server /data --console-address ":9001"
    @echo "MinIO started: http://localhost:9001 (minioadmin/minioadmin)"

# Start a local Vault for KMS testing
vault:
    docker run -d --name vault \
        -p 8200:8200 \
        -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
        hashicorp/vault
    @echo "Vault started: http://localhost:8200 (token: myroot)"

# Start LocalStack for AWS testing
localstack:
    docker run -d --name localstack \
        -p 4566:4566 \
        -e SERVICES=kms,sts,s3 \
        localstack/localstack
    @echo "LocalStack started: http://localhost:4566"

# Stop all dev containers
dev-stop:
    docker stop minio vault localstack 2>/dev/null || true
    docker rm minio vault localstack 2>/dev/null || true

# Generate self-signed TLS certificate
gen-cert:
    cargo run --all-features -- generate-cert \
        --hostname localhost \
        --output-dir ./certs

# Show project statistics
stats:
    @echo "=== Lines of Code ==="
    @tokei src tests
    @echo ""
    @echo "=== Binary Size ==="
    @ls -lh target/release/rustberg 2>/dev/null || echo "Run 'just release' first"
    @echo ""
    @echo "=== Dependencies ==="
    @cargo tree --depth 1 | wc -l | xargs echo "Direct dependencies:"

# ============================================================================
# CI/CD Helpers
# ============================================================================

# Prepare for release (run all checks)
pre-release version: check
    @echo "Preparing release {{version}}..."
    @grep -q "version = \"{{version}}\"" Cargo.toml || \
        (echo "ERROR: Update version in Cargo.toml first" && exit 1)
    @echo "✅ Ready for release {{version}}"

# Publish to crates.io (dry-run)
publish-dry:
    cargo publish --dry-run --all-features

# Publish to crates.io
publish:
    cargo publish --all-features

# Create git tag
tag version:
    git tag -a v{{version}} -m "Release v{{version}}"
    git push origin v{{version}}
