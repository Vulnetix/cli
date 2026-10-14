#!/usr/bin/env bash
#
# benchmark/sca-fixtures.sh — time `vulnetix sca` across the SCA manifest
# fixtures and record a normalised fingerprint of every result, so a faster
# build can be checked for result parity against a baseline.
#
# Usage:
#   ./benchmark/sca-fixtures.sh <binary> <label> [fixture ...]
#   ./benchmark/sca-fixtures.sh --compare <labelA> <labelB>
#
# Each fixture runs on a fresh copy without a previous scan's .vulnetix.
# Output lands in benchmark/results/sca/<label>/: timings.tsv (wall ms, exit
# code, component/vulnerability counts, HTTP request count), the CycloneDX
# document, stderr (with the VULNETIX_HTTP_TRACE request timeline) and a
# sorted fingerprint (.fp) of components and vulnerabilities.
#
# Env:
#   VULNETIX_SCA_FIXTURES  fixture root (default ../Vulnetix-extra/sca-manifest-fixtures)
#   SCA_ARGS               extra arguments for `vulnetix sca`
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)/results/sca
FIX=${VULNETIX_SCA_FIXTURES:-$(cd "$(dirname "$0")/../.." && pwd)/../Vulnetix-extra/sca-manifest-fixtures}

if [ "${1:-}" = "--compare" ]; then
  A=$ROOT/$2; B=$ROOT/$3; same=0; diff=0
  for fp in "$A"/*.fp; do
    f=$(basename "$fp" .fp)
    [ -f "$B/$f.fp" ] || continue
    if cmp -s "$fp" "$B/$f.fp"; then same=$((same + 1)); else
      diff=$((diff + 1)); echo "== $f differs"; diff "$fp" "$B/$f.fp" | head -20
    fi
  done
  echo "parity: $same identical, $diff differ"
  join -t $'\t' <(tail -n +2 "$A/timings.tsv" | LC_ALL=C sort -k1,1) <(tail -n +2 "$B/timings.tsv" | LC_ALL=C sort -k1,1) |
    awk -F'\t' '{a+=$2; b+=$7; printf "%-28s %7d ms -> %7d ms  (%5.1f%%)  http %s -> %s\n", $1, $2, $7, ($2-$7)*100/$2, $6, $11}
                END{printf "TOTAL %d ms -> %d ms  (%.1f%% faster)\n", a, b, (a-b)*100/a}'
  exit 0
fi

BIN=$(realpath "$1"); LABEL=$2; shift 2
OUT=$ROOT/$LABEL; WORK=$ROOT/work-$LABEL
rm -rf "$OUT" "$WORK"; mkdir -p "$OUT" "$WORK"
if [ $# -eq 0 ]; then
  set -- $(cd "$FIX" && for d in */; do d=${d%/}; [ "$d" = scripts ] && continue; echo "$d"; done)
fi
printf "fixture\tms\texit\tcomponents\tvulns\thttp\n" > "$OUT/timings.tsv"
for f in "$@"; do
  cp -r "$FIX/$f" "$WORK/$f"; rm -rf "$WORK/$f/.vulnetix"
  s=$(date +%s%N)
  # shellcheck disable=SC2086
  VULNETIX_HTTP_TRACE=1 "$BIN" sca --path "$WORK/$f" --no-progress -o json-cyclonedx ${SCA_ARGS:-} >"$OUT/$f.cdx.json" 2>"$OUT/$f.err"
  rc=$?
  e=$(date +%s%N)
  ms=$(( (e - s) / 1000000 ))
  jq -r '([.components[]? | "C " + (.purl // .name)] | sort | .[]),
         ([.vulnerabilities[]? | "V \(.id)|\([.affects[]?.ref]|sort|join(","))|\([.ratings[]?|"\(.method):\(.severity):\(.score)"]|sort|join(","))|\([.properties[]?|"\(.name)=\(.value)"]|sort|join(","))"] | sort | .[])' \
     "$OUT/$f.cdx.json" > "$OUT/$f.fp" 2>/dev/null || echo "NOJSON" > "$OUT/$f.fp"
  nc=$(grep -c '^C ' "$OUT/$f.fp"); nv=$(grep -c '^V ' "$OUT/$f.fp"); nh=$(grep -c '^\[http#' "$OUT/$f.err")
  printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$f" "$ms" "$rc" "$nc" "$nv" "$nh" | tee -a "$OUT/timings.tsv"
done
rm -rf "$WORK"
awk -F'\t' 'NR>1{t+=$2;n++} END{printf "TOTAL %d fixtures, %d ms, mean %d ms\n", n, t, t/n}' "$OUT/timings.tsv" | tee "$OUT/total.txt"
