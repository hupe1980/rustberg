#!/usr/bin/env bash
# Render the Homebrew formula for a release from its checksums.
#
#   packaging/homebrew/formula.sh 0.4.0 checksums.txt > Formula/rustberg.rb
set -euo pipefail
version="${1:?usage: formula.sh <version> <checksums.txt>}"
sums="${2:?usage: formula.sh <version> <checksums.txt>}"
out="$(sed "s/@VERSION@/$version/g" "$(dirname "$0")/rustberg.rb.in")"
for archive in rustberg-darwin-aarch64 rustberg-linux-aarch64 rustberg-linux-x86_64; do
  sum="$(awk -v a="$archive.tar.gz" '$2 == a || $2 == "*" a { print $1 }' "$sums")"
  if ! [[ "$sum" =~ ^[0-9a-f]{64}$ ]]; then
    echo "formula: no checksum for $archive.tar.gz in $sums" >&2
    exit 1
  fi
  out="${out//@SHA256_$archive@/$sum}"
done
if grep -q '@[A-Za-z0-9_-]*@' <<<"$out"; then
  echo "formula: a placeholder was left" >&2
  exit 1
fi
printf '%s\n' "$out"
