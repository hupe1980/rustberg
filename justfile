# Rustberg — `just --list` shows every recipe.

default:
    @just --list

# ── Develop ─────────────────────────────────────────────────────────────────

# Run the server, e.g. `just run --dev --insecure-http`
run *ARGS:
    cargo run --all-features -- {{ARGS}}

# Build the console into ui/dist, which the binary embeds (Node 24)
ui:
    cd ui && npm ci --no-audit --no-fund && npm run build

# The console with live reload, against a server on port 8000
ui-dev:
    cd ui && npm run dev

# Retake the console screenshots in the docs, from a real server (needs Chrome)
shots: ui
    cargo build
    cd ui && npm run shots

# ── Check ───────────────────────────────────────────────────────────────────

# The local gate: format, clippy, tests, doc tests
check: fmt-check lint test test-doc
    @echo "✅ All checks passed!"

# Formatting, as CI checks it
fmt-check:
    cargo fmt --all -- --check

# Clippy over every target and feature, warnings denied
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Every Rust test
test:
    cargo test --all-features

# Doc tests
test-doc:
    cargo test --doc --all-features

# PyIceberg and DuckDB against a freshly built binary
test-clients:
    cargo build --all-features
    RUSTBERG_BINARY=target/debug/rustberg uv run pytest tests/python -v --tb=short

# The console's types, components, contrast and accessibility
ui-test:
    cd ui && npm run check && npm test

# The Postgres catalog and two-replica suites (Docker)
test-postgres:
    cargo test --all-features --test postgres_catalog_tests --test clustered_tests -- --ignored

# Trino against the binary (Docker)
test-trino:
    cargo test --test trino_integration_tests --all-features -- --ignored --nocapture

# The performance gate, as CI runs it
test-perf:
    cargo test --release --all-features --test performance_tests -- --ignored --nocapture --test-threads=1

# Every optional feature builds on its own
features:
    #!/usr/bin/env bash
    set -euo pipefail
    # Features unify across the graph, so one can build under --all-features and
    # fail alone. The list is read from Cargo.toml (aggregates skipped), so a new
    # feature is covered without editing this.
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

# The crate builds on its declared minimum Rust version
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

# Advisories, licences, bans and sources (deny.toml), over every feature
deny:
    cargo deny --all-features check

# Rustdoc, failing on a broken link as CI does
doc:
    RUSTDOCFLAGS=-Dwarnings cargo doc --all-features --no-deps --open

# Has a pinned upstream Iceberg specification moved? (.github/spec-pins.toml)
spec-check:
    ./.github/spec-drift.sh

# Re-stamp the pinned digests — only after reading what changed
spec-pins:
    ./.github/spec-drift.sh --update

# ── Site ────────────────────────────────────────────────────────────────────

# Serve the docs site with live reload (zola)
site:
    cd site && zola serve

# Build the site into site/public
site-build:
    cd site && zola build

# Check every internal and external link
site-check:
    cd site && zola check

# Re-vendor the syntax themes after changing them in site/config.toml
site-syntax: site-build
    #!/usr/bin/env bash
    set -euo pipefail
    # Why mixins rather than two stylesheets: see the header written below.
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

# ── Release ─────────────────────────────────────────────────────────────────

# Build the image and check it starts, reports healthy and serves
docker-smoke tag="smoke":
    #!/usr/bin/env bash
    set -euo pipefail
    # Proves the image starts and serves, not just that the binary links. CI runs this.
    docker build -t rustberg:{{tag}} .
    docker rm -f rustberg-smoke >/dev/null 2>&1 || true
    docker run -d --name rustberg-smoke -p 8000:8000 \
      -e RUSTBERG_INSECURE_HTTP=true rustberg:{{tag}}
    trap 'docker rm -f rustberg-smoke >/dev/null 2>&1 || true' EXIT
    for _ in $(seq 1 30); do
      state=$(docker inspect -f '{{{{.State.Health.Status}}' rustberg-smoke)
      [ "$state" = healthy ] && break
      [ "$state" = unhealthy ] && break
      sleep 2
    done
    docker logs rustberg-smoke
    test "$(docker inspect -f '{{{{.State.Health.Status}}' rustberg-smoke)" = healthy
    # Authentication is on by default, so 401 is the proof that the router is
    # serving — a connection refused or a 500 would not be.
    code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/v1/config)
    echo "GET /v1/config -> $code"
    test "$code" = 401
    echo "✅ the image starts, reports healthy, and serves"

# Verify the crate package
publish-dry:
    cargo publish --dry-run --locked --all-features

# Tag and push a release; the release workflow builds and publishes it
tag version:
    git tag -a v{{version}} -m "Release v{{version}}"
    git push origin v{{version}}
