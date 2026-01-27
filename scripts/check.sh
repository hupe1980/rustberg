#!/usr/bin/env bash
# Rustberg pre-commit/pre-push checks
# Run this locally before pushing to catch CI failures early
#
# Usage:
#   ./scripts/check.sh          # Run all checks
#   ./scripts/check.sh --quick  # Run only fast checks (fmt, clippy, check)
#   ./scripts/check.sh --test   # Run checks + tests
#
# To install as pre-commit hook:
#   ln -sf ../../scripts/check.sh .git/hooks/pre-commit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
QUICK=false
TEST=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick|-q) QUICK=true; shift ;;
        --test|-t) TEST=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

print_step() {
    echo -e "${YELLOW}▶ $1${NC}"
}

print_ok() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_err() {
    echo -e "${RED}✗ $1${NC}"
}

run_check() {
    local name="$1"
    shift
    print_step "$name"
    if "$@"; then
        print_ok "$name passed"
    else
        print_err "$name failed"
        exit 1
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Rustberg CI Checks"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Essential checks (always run)
run_check "Formatting" cargo fmt --all -- --check
run_check "Clippy" cargo clippy --all-targets --all-features -- -D warnings
run_check "Compilation" cargo check --all-features --workspace

if $QUICK; then
    echo ""
    print_ok "Quick checks passed!"
    exit 0
fi

# Additional checks
run_check "Documentation" cargo doc --no-deps --all-features 2>&1 | head -50

if $TEST; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Running Tests"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    run_check "Unit Tests" cargo test --all-features --workspace --lib --bins
    
    # Only run integration tests if Docker is available
    if command -v docker &> /dev/null && docker info &> /dev/null; then
        run_check "Integration Tests" cargo test --all-features --workspace -- --test-threads=1
    else
        echo -e "${YELLOW}⚠ Docker not available, skipping integration tests${NC}"
    fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_ok "All checks passed!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
