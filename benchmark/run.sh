#!/usr/bin/env bash
#
# benchmark/run.sh — Benchmark the vulnetix CLI subcommands against this repo.
#
# Runs five scenarios, each on a FRESH copy of the repo (autofix mutates go.mod
# + writes .vulnetix/, so every run starts clean), records wall-clock timing
# across RUNS iterations, and writes a Markdown report under benchmark/results/.
#
# Scenarios (in order):
#   1. sca                  — Software Composition Analysis only
#   2. sast                 — Static Application Security Testing only
#   3. sca  + autofix(safest)— SCA with the conservative autofix strategy
#   4. scan                 — full local scan
#   5. scan + autofix(safest)— full scan with the conservative autofix strategy
#
# Usage:
#   ./benchmark/run.sh                         # `vulnetix` from PATH (brew install)
#   RUNS=5 ./benchmark/run.sh                  # more iterations
#   VULNETIX_BIN=./bin/vulnetix ./benchmark/run.sh   # benchmark a local build
#   BENCH_TIMEOUT=600 ./benchmark/run.sh       # per-run timeout (seconds)
#   GOPROXY=https://proxy.golang.org,direct ./benchmark/run.sh   # isolate CLI from a slow proxy
#
# Env:
#   VULNETIX_BIN   binary to benchmark              (default: vulnetix on PATH)
#   RUNS           timed iterations per scenario    (default: 3; run 1 is "cold")
#   BENCH_TIMEOUT  per-run timeout, seconds         (default: 900)
#   GOPROXY        inherited as-is — autofix install time depends on it
#
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
VULNETIX_BIN=${VULNETIX_BIN:-vulnetix}
RUNS=${RUNS:-3}
BENCH_TIMEOUT=${BENCH_TIMEOUT:-900}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESULTS_DIR="$SCRIPT_DIR/results"
LOGDIR="$RESULTS_DIR/logs-$STAMP"
REPORT="$RESULTS_DIR/report-$STAMP.md"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vulnetix-bench.XXXXXX")
mkdir -p "$LOGDIR"
trap 'rm -rf "$WORK"' EXIT

if ! command -v "$VULNETIX_BIN" >/dev/null 2>&1 && [ ! -x "$VULNETIX_BIN" ]; then
  echo "error: vulnetix binary not found: $VULNETIX_BIN" >&2; exit 1
fi
VER=$("$VULNETIX_BIN" version 2>/dev/null | grep -oiE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
HEAD=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')

echo "vulnetix: $VULNETIX_BIN (${VER:-?}) | runs=$RUNS | timeout=${BENCH_TIMEOUT}s | GOPROXY=${GOPROXY:-<default>}"

# Fresh copy of the repo, excluding heavy/dirty dirs.
prepare_copy() {
  local dst=$1
  rm -rf "$dst"; mkdir -p "$dst"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
      --exclude '.git' --exclude '.vulnetix' --exclude 'node_modules' \
      --exclude 'benchmark/results' "$REPO_ROOT/" "$dst/"
  else
    cp -a "$REPO_ROOT/." "$dst/"
    rm -rf "$dst/.git" "$dst/.vulnetix" "$dst/node_modules" "$dst/benchmark/results"
  fi
}

median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{ if(NR%2){print a[(NR+1)/2]} else {printf "%d", (a[NR/2]+a[NR/2+1])/2} }'; }
fmt_s()  { awk -v ms="$1" 'BEGIN{printf "%.1fs", ms/1000}'; }

{
  echo "# vulnetix CLI benchmark"
  echo
  echo "- **Binary:** \`$VULNETIX_BIN\` (${VER:-?})"
  echo "- **Target repo:** $(basename "$REPO_ROOT") @ \`$HEAD\`"
  echo "- **Host:** $(uname -sm), $(nproc 2>/dev/null || echo '?') cores"
  echo "- **Runs per scenario:** $RUNS (run 1 = cold) · **Timeout:** ${BENCH_TIMEOUT}s/run"
  echo "- **GOPROXY:** \`${GOPROXY:-<inherited default>}\` (affects autofix install time only)"
  echo "- **Generated:** $STAMP"
  echo
  echo "Each run executes on a fresh copy of the repo (autofix mutates go.mod). Times are"
  echo "wall-clock of the whole subcommand — including cold start, the VDB API round-trip,"
  echo "and (autofix only) the package-manager resolve via GOPROXY."
  echo
  echo "| # | Scenario | Command | runs | min | median | max | findings | exit | notes |"
  echo "|---|----------|---------|------|-----|--------|-----|----------|------|-------|"
} > "$REPORT"

idx=0
bench() {
  local name=$1; shift
  local cmd="$*"
  idx=$((idx+1))
  echo; echo "▶ [$idx] $name"; echo "   \$ $cmd"
  local times=() rc=0 metric="n/a" note=""
  for run in $(seq 1 "$RUNS"); do
    local dst="$WORK/$name-$run" log="$LOGDIR/${name}-run${run}.log" s e dur
    prepare_copy "$dst"
    s=$(date +%s%3N)
    ( cd "$dst" && timeout "$BENCH_TIMEOUT" bash -c "$cmd" ) >"$log" 2>&1
    rc=$?
    e=$(date +%s%3N); dur=$((e - s))
    times+=("$dur")
    local m; m=$(grep -oiE '[0-9]+ (sast )?finding' "$log" | head -1 | grep -oE '[0-9]+' || true)
    [ -n "$m" ] && metric="$m"
    [ "$rc" = 124 ] && note="hit timeout"
    printf "   run %d: %s (rc=%d)\n" "$run" "$(fmt_s "$dur")" "$rc"
  done
  local mn mx md
  mn=$(printf '%s\n' "${times[@]}" | sort -n | head -1)
  mx=$(printf '%s\n' "${times[@]}" | sort -n | tail -1)
  md=$(median "${times[@]}")
  printf '| %d | %s | `%s` | %d | %s | %s | %s | %s | %d | %s |\n' \
    "$idx" "$name" "$cmd" "$RUNS" "$(fmt_s "$mn")" "$(fmt_s "$md")" "$(fmt_s "$mx")" "$metric" "$rc" "$note" >> "$REPORT"
}

V="$VULNETIX_BIN"
bench "sca"                  "$V sca --no-banner"
bench "sast"                 "$V sast --no-banner"
bench "sca + autofix:safest" "$V sca --sca-autofix --sca-autofix-strategy safest --yes --no-banner"
bench "scan"                 "$V scan --no-banner"
bench "scan + autofix:safest" "$V scan --sca-autofix --sca-autofix-strategy safest --yes --no-banner"

{
  echo
  echo "_Per-run logs: \`${LOGDIR#"$REPO_ROOT/"}\`. Non-zero exit is normal — quality gates"
  echo "(e.g. \`--block-malware\`) and autofix intentionally exit non-zero; timing is unaffected._"
} >> "$REPORT"

echo; echo "✅ Report written: $REPORT"; echo
cat "$REPORT"
