#!/usr/bin/env bash
# Fails when an upstream document this project's claims are read from has moved
# since it was last retrieved.
#
# Reads `.github/spec-pins.toml`; see that file for why this pins digests rather
# than committing the documents, and for what to do when it fires.
#
# One implementation, two callers: the daily `spec-drift` job in
# `security.yml`, and `just spec-check` for a maintainer who wants the answer
# now. A second copy of this logic would be one edit away from the two
# disagreeing about whether the tree is current.
#
#   --update   rewrite the digests in place instead of failing, for use after
#              the change has been read. Never run this from CI.
set -uo pipefail

cd "$(dirname "$0")/.."
PINS=".github/spec-pins.toml"
update=false
[[ "${1:-}" == "--update" ]] && update=true

# `shasum` on macOS, `sha256sum` on the CI runners. Picking one at the top
# rather than per call, so a host with neither fails here with a sentence
# instead of failing per-document with an empty digest that matches nothing.
if command -v sha256sum >/dev/null 2>&1; then
    digest() { sha256sum | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    digest() { shasum -a 256 | cut -d' ' -f1; }
else
    echo "neither sha256sum nor shasum is available" >&2
    exit 2
fi

# The pin file is TOML, and this deliberately does not parse TOML: the shape is
# fixed and written by hand here, so three greps beat a dependency the CI image
# would have to carry. A malformed entry yields an empty field, which is caught
# below rather than silently skipped.
names=()
urls=()
sums=()
while IFS= read -r line; do
    case "$line" in
        name*) names+=("$(sed 's/.*= *"\(.*\)"/\1/' <<<"$line")") ;;
        url*) urls+=("$(sed 's/.*= *"\(.*\)"/\1/' <<<"$line")") ;;
        sha256*) sums+=("$(sed 's/.*= *"\(.*\)"/\1/' <<<"$line")") ;;
    esac
done < <(grep -E '^(name|url|sha256) *=' "$PINS")

if [[ ${#names[@]} -eq 0 ]]; then
    echo "no pins found in $PINS — refusing to report success" >&2
    exit 2
fi
if [[ ${#names[@]} -ne ${#urls[@]} || ${#names[@]} -ne ${#sums[@]} ]]; then
    echo "$PINS has ${#names[@]} names, ${#urls[@]} urls and ${#sums[@]} digests" >&2
    exit 2
fi

moved=0
for i in "${!names[@]}"; do
    name="${names[$i]}"
    url="${urls[$i]}"
    want="${sums[$i]}"

    # Downloaded to a file rather than captured into a variable, because command
    # substitution strips trailing newlines: every one of these documents ends
    # with one, so hashing `$(curl …)` reports drift on all four, every run,
    # for ever. A check that cries wolf on an unchanged tree is worse than no
    # check, and this one did until it was run.
    #
    # `--fail` turns an HTTP error into a non-zero exit rather than a body that
    # gets hashed, which would otherwise report drift on every 404 and, worse,
    # report *no* drift on an empty 200.
    tmp=$(mktemp)
    if ! curl -sSL --fail --max-time 60 -o "$tmp" "$url"; then
        echo "FETCH FAILED  $name" >&2
        echo "              $url" >&2
        rm -f "$tmp"
        moved=$((moved + 1))
        continue
    fi
    got=$(digest <"$tmp")
    rm -f "$tmp"

    if [[ "$got" == "$want" ]]; then
        echo "unchanged     $name"
    elif $update; then
        # Anchored to this pin's own digest line, so two documents that happen
        # to share a digest cannot cross-write each other's entry.
        sed -i.bak "s|\"$want\"|\"$got\"|" "$PINS" && rm -f "$PINS.bak"
        echo "restamped     $name"
        echo "              $want -> $got"
    else
        echo "MOVED         $name" >&2
        echo "              expected $want" >&2
        echo "              got      $got" >&2
        moved=$((moved + 1))
    fi
done

if [[ $moved -gt 0 ]] && ! $update; then
    cat >&2 <<EOF

$moved upstream document(s) moved since they were last retrieved.

This is the control for the hazard that conformance claims rot silently: the
REST OpenAPI document carries no version and produces no release event, so
nothing else would have told you.

  1. Read what changed. The retrieved copy is in concepts/references/:
       curl -sL <url> | git diff --no-index concepts/references/<name> -
  2. Decide whether it touches anything Rustberg implements or advertises, and
     open a roadmap item if it does.
  3. Re-retrieve the corpus, then re-stamp:
       just spec-pins
EOF
    exit 1
fi

$update && echo "pins updated — commit .github/spec-pins.toml"
exit 0
