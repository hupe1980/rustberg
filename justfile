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

# Run the Postgres catalog and two-replica suites (requires Docker)
test-postgres:
    cargo test --all-features --test postgres_catalog_tests --test clustered_tests -- --ignored

# Run the performance gate the way CI does
test-perf:
    cargo test --release --all-features --test performance_tests -- --ignored --nocapture --test-threads=1

# Run the client conformance suites against a freshly built binary
test-clients:
    cargo build --all-features
    RUSTBERG_BINARY=target/debug/rustberg uv run pytest tests/python -v --tb=short

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

# Check every optional feature on its own
features:
    #!/usr/bin/env bash
    set -euo pipefail
    # Cargo features are additive and unify across a dependency graph, so a
    # feature that compiles under --all-features can be broken alone: some other
    # crate was switching on the thing it needed. --all-features and
    # --no-default-features are the two ends of the range, and the middle is
    # where that breaks.
    #
    # The list is read from Cargo.toml rather than written here. A hardcoded one
    # silently stops covering the feature added after it — which is how
    # `remote-signing` went unchecked while this recipe claimed to check
    # everything. `default` and `storage-all` are skipped: both are aggregates
    # of entries already in the list, so checking them proves nothing new.
    cargo check --no-default-features
    features=$(cargo metadata --no-deps --format-version 1 \
      | python3 -c 'import json,sys; print(" ".join(
            f for f in json.load(sys.stdin)["packages"][0]["features"]
            if f not in ("default", "storage-all")))')
    for feature in $features; do
      echo "▶ $feature"
      cargo check --quiet --no-default-features --features "$feature"
    done
    cargo check --quiet --all-features
    echo "✅ Every feature builds alone: $features"

# Verify the crate still compiles on its declared minimum Rust version
msrv:
    #!/usr/bin/env bash
    set -euo pipefail
    msrv=$(grep -E '^rust-version' Cargo.toml | cut -d'"' -f2)
    if ! rustup run "$msrv" cargo --version >/dev/null 2>&1; then
      echo "Install it first: rustup toolchain install $msrv"
      exit 1
    fi
    rustup run "$msrv" cargo check --all-features
    echo "✅ Builds on $msrv"

# Security audit
# Advisories, using the same tool and ignore list the CI gate uses.
audit:
    cargo deny --all-features check advisories

# Check for outdated dependencies
outdated:
    cargo outdated

# Deny check (advisories, bans, licences, sources).
#
# `--all-features`, because the ban list is what keeps OpenSSL and native-tls
# out of *every* feature combination, and it can only do that over a graph that
# has the optional dependencies in it.
deny:
    cargo deny --all-features check

# ============================================================================
# Documentation
# ============================================================================

# Build documentation, failing on a broken intra-doc link as CI does
doc:
    RUSTDOCFLAGS=-Dwarnings cargo doc --all-features --no-deps --open

# ============================================================================
# Site
# ============================================================================

# Serve the site locally with live reload (requires zola)
site:
    cd site && zola serve

# Build the site into site/public
site-build:
    cd site && zola build

# Validate every internal and external link on the site
site-check:
    cd site && zola check

# Re-vendor the syntax themes after changing them in site/config.toml
site-syntax: site-build
    #!/usr/bin/env bash
    set -euo pipefail
    # Zola's `class` highlighting stamps both theme class sets onto every token,
    # so light and dark cannot be selected with two `<link media>` elements —
    # that follows the OS preference and breaks the moment a reader uses the
    # theme toggle. Wrapping each theme in a mixin lets one stylesheet scope
    # them; see the header this writes into the generated file.
    cd site
    out=sass/_syntax.scss
    cat > "$out" <<'NOTES'
    // Syntax highlighting, vendored from Zola's generated theme stylesheets.
    //
    // Zola's `class` highlighting style stamps *both* class sets onto every token
    // — `<span class="z-l-1 z-d-3">` — so the light and dark rules are always both
    // present in the markup and cannot be selected between with a `<link media>`
    // alone. That works for the OS preference and breaks the moment a reader uses
    // the theme toggle.
    //
    // Wrapping each theme in a mixin lets `main.scss` include it under the right
    // root selector, so a dark rule becomes `:root[data-theme="dark"] .z-d-1` and
    // beats the light one on both specificity and order — in both directions.
    //
    // Generated. Run `just site-syntax` after changing the themes in config.toml.

    NOTES
    for theme in light dark; do
      # The generated file opens with a three-line banner naming the theme.
      echo "@mixin syntax-$theme {" >> "$out"
      # Drop the three-line banner and any blank lines under it, then indent
      # only the non-empty lines so nothing carries trailing whitespace.
      sed -e '1,3d' "public/giallo-$theme.css" \
        | sed -e '/./,$!d' -e 's/^./  &/' >> "$out"
      printf '}\n\n' >> "$out"
    done
    echo "regenerated site/sass/_syntax.scss"

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

# Build Docker image
docker-build tag="latest":
    docker build -t rustberg:{{tag}} .

# Start the image the way the README says to, and check that it serves
docker-smoke tag="smoke":
    #!/usr/bin/env bash
    set -euo pipefail
    # `--version` and `--help` prove the binary links; they do not prove the
    # image *starts*, which is a different question and the one that has been
    # wrong before. This is what CI runs.
    docker build -t rustberg:{{tag}} .
    docker rm -f rustberg-smoke >/dev/null 2>&1 || true
    docker run -d --name rustberg-smoke -p 8000:8000 \
      -e RUSTBERG_INSECURE_HTTP=true rustberg:{{tag}}
    trap 'docker rm -f rustberg-smoke >/dev/null 2>&1 || true' EXIT
    for _ in $(seq 1 30); do
      state=$(docker inspect -f '{{{{.State.Health.Status}}}}' rustberg-smoke)
      [ "$state" = healthy ] && break
      [ "$state" = unhealthy ] && break
      sleep 2
    done
    docker logs rustberg-smoke
    test "$(docker inspect -f '{{{{.State.Health.Status}}}}' rustberg-smoke)" = healthy
    # Authentication is on by default, so 401 is the proof that the router is
    # serving — a connection refused or a 500 would not be.
    code=$(curl -s -o /dev/null -w '%{{{{http_code}}}}' http://localhost:8000/v1/config)
    echo "GET /v1/config -> $code"
    test "$code" = 401
    echo "✅ the image starts, reports healthy, and serves"

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

# Stop all dev containers
dev-stop:
    docker stop minio 2>/dev/null || true
    docker rm minio 2>/dev/null || true

# Generate self-signed TLS certificate
gen-cert:
    cargo run --all-features -- generate-cert \
        --common-name localhost \
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
