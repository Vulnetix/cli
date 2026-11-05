#!/usr/bin/env bash
# Proves scoped scans lose nothing: the sast legs plus the rest leg must report
# exactly what a full sast run reports, and every sca manifest must land in one leg.
#   ci-scope-union.sh <sast-fixture-dir> <sca-fixture-dir>
set -uo pipefail
sast_dir=$1
sca_dir=$2
tmp=$(mktemp -d)
flags=(--no-banner --disable-memory --no-cache --no-progress --depth 12)
key='.runs[].results[]|[.ruleId,.locations[0].physicalLocation.artifactLocation.uri,(.locations[0].physicalLocation.region.startLine|tostring)]|join("|")'
fail=0

cd "$sast_dir" || exit 2
vulnetix sast "${flags[@]}" >/dev/null 2>&1
jq -r "$key" .vulnetix/sast.sarif | sort >"$tmp/full"
langs=(python go javascript java php csharp shell ruby rust c-cpp kotlin)
for l in "${langs[@]}"; do
  vulnetix sast "${flags[@]}" --language "$l" >/dev/null 2>&1
  [ -f ".vulnetix/sast.$l.sarif" ] && jq -r "$key" ".vulnetix/sast.$l.sarif" >>"$tmp/legs"
done
vulnetix sast "${flags[@]}" --not-language "$(IFS=,; echo "${langs[*]}")" >/dev/null 2>&1
for f in .vulnetix/sast.not-*.sarif; do [ -f "$f" ] && jq -r "$key" "$f" >>"$tmp/legs"; done
sort "$tmp/legs" -o "$tmp/legs"
echo "sast: full $(wc -l <"$tmp/full"), legs $(wc -l <"$tmp/legs")"
if ! diff -q "$tmp/full" "$tmp/legs" >/dev/null; then
  echo "::error::the sast legs differ from a full scan"
  diff "$tmp/full" "$tmp/legs" | head -20
  fail=1
fi

cd "$sca_dir" || exit 2
list() { vulnetix sca --no-banner --disable-memory --no-progress --depth 6 --dry-run --show-detected "$@" 2>&1 | grep -E '^  [^ ]+ +[a-z]' | awk '{print $1}' | sort -u; }
list >"$tmp/sca-full"
managers=(bun bundler cargo cocoapods composer go gradle hex maven npm nuget pip pipenv pnpm poetry pub swift uv yarn)
for m in "${managers[@]}"; do list --package-manager "$m" >>"$tmp/sca-legs"; done
list --not-package-manager "$(IFS=,; echo "${managers[*]}")" >>"$tmp/sca-legs"
sort "$tmp/sca-legs" -o "$tmp/sca-legs"
echo "sca: full $(wc -l <"$tmp/sca-full"), legs $(wc -l <"$tmp/sca-legs")"
if ! diff -q "$tmp/sca-full" "$tmp/sca-legs" >/dev/null; then
  echo "::error::the sca legs do not partition the manifests"
  diff "$tmp/sca-full" "$tmp/sca-legs" | head -20
  fail=1
fi
exit "$fail"
