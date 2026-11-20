#!/usr/bin/env bash
# Runs Apache's REST Compatibility Kit against a running Rustberg.
#
#   .github/rck.sh <catalog-uri> <warehouse> [bearer-token]
#
# The pinned tag, the behaviour flags and the exclusions all come from
# .github/rck.properties. Needs a JDK (17+) and git. The client reads table
# files directly in some tests, so <warehouse> must be a path both the server
# and this machine see the same way.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
props="$here/rck.properties"
uri="$1"
warehouse="$2"
token="${3:-}"

tag="$(grep -E '^iceberg\.tag=' "$props" | cut -d= -f2-)"
dir="${RCK_ICEBERG_DIR:-$here/../target/rck/iceberg-$tag}"
if [ ! -d "$dir/.git" ]; then
  git clone --quiet --depth 1 --branch "$tag" https://github.com/apache/iceberg.git "$dir"
fi

args=()
while IFS='=' read -r key value; do
  [ "$key" = rck.exclude ] && continue
  args+=("-D$key=$value")
done < <(grep -E '^rck\.' "$props")
excluded="$(grep -E '^rck\.exclude=' "$props" | cut -d= -f2- | tr ',' '\n' | sed '/^$/d')"
if [ -n "$token" ]; then
  args+=("-Drck.token=$token")
fi

cd "$dir"
results="open-api/build/test-results/test"
rm -rf "$results"
./gradlew --no-daemon --console=plain -I "$here/rck-init.gradle" \
  :iceberg-open-api:test --tests RESTCompatibilityKitSuite \
  -Drck.local=false -Drck.uri="$uri" -Drck.warehouse="$warehouse" "${args[@]}"

# Judge the results: every test is a `<testcase>`, every failure a `<failure>`
# inside it. A failure is accepted only if its test is excluded by name.
total=0
unexpected=()
stale=()
for file in "$results"/TEST-*.xml; do
  class="$(basename "$file" .xml | sed 's/^TEST-//; s/.*\.//')"
  while IFS='|' read -r name failed; do
    total=$((total + 1))
    id="$class.${name%%(*}"
    if grep -qxF "$id" <<<"$excluded"; then
      [ "$failed" = 0 ] && stale+=("$id")
    elif [ "$failed" = 1 ]; then
      unexpected+=("$id")
    fi
  done < <(awk '
    /<testcase / { if (name != "") print name "|" failed; match($0, / name="[^"]*"/); name = substr($0, RSTART + 7, RLENGTH - 8); failed = 0 }
    /<failure/ { failed = 1 }
    END { if (name != "") print name "|" failed }' "$file")
done

echo "RCK: $total tests, ${#unexpected[@]} unexpected failures, $(grep -c . <<<"$excluded" || true) excluded"
[ "$total" -gt 0 ] || { echo "The RCK ran zero tests."; exit 1; }
for id in "${stale[@]}"; do echo "excluded but passing — remove its exclusion: $id"; done
for id in "${unexpected[@]}"; do echo "FAILED: $id"; done
[ "${#unexpected[@]}" -eq 0 ] && [ "${#stale[@]}" -eq 0 ]
