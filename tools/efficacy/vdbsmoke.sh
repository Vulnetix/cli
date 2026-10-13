#!/usr/bin/env bash
# vdbsmoke: for each vdb command and well-known vulnerability, check that the
# pretty output renders what -o json returns. It catches the class of bug where a
# renderer reads keys the API never sends and prints "No X found" (or a header
# with a blank identifier) for a vulnerability that has data.
#
#   tools/efficacy/vdbsmoke.sh ./vulnetix /tmp/vdbsmoke
set -u
BIN=${1:-./vulnetix}
OUT=${2:-/tmp/vdbsmoke}
IDS=${IDS:-"CVE-2021-44228 CVE-2014-0160 CVE-2023-44487 CVE-2024-3094 CVE-2022-22965 GHSA-jfh8-3a1q-hjz9"}
CMDS=${CMDS:-"vuln|exploits|fixes|timeline|affected|advisories|workarounds|cwe guidance|remediation plan|scorecard|kev get|gcve|attack-techniques get|virtual-patches get|countermeasures get"}
mkdir -p "$OUT"
fail=0
total=0
IFS='|' read -r -a CMDARR <<<"$CMDS"
for cmd in "${CMDARR[@]}"; do
  for id in $IDS; do
    total=$((total + 1))
    tag=$(echo "$cmd $id" | tr ' ' '_')
    # shellcheck disable=SC2086
    NO_COLOR=1 timeout 120 "$BIN" vdb $cmd "$id" --no-progress -o json >"$OUT/$tag.json" 2>"$OUT/$tag.json.err"
    jrc=$?
    # shellcheck disable=SC2086
    NO_COLOR=1 timeout 120 "$BIN" vdb $cmd "$id" --no-progress >"$OUT/$tag.txt" 2>"$OUT/$tag.txt.err"
    prc=$?
    problems=()
    # A CVE that no KEV catalogue lists is a valid, honest answer, not a failure.
    # An id the database has no record of is a valid, honest answer, not a failure.
    if grep -qE "none of the KEV catalogues|API error \(404\): Vulnerability not found" "$OUT/$tag.json.err" "$OUT/$tag.txt.err" 2>/dev/null; then
      continue
    fi
    [ $jrc -ne 0 ] && problems+=("json mode failed (exit $jrc): $(tail -1 "$OUT/$tag.json.err" | cut -c1-100)")
    [ $prc -ne 0 ] && problems+=("pretty mode failed (exit $prc): $(tail -1 "$OUT/$tag.txt.err" | cut -c1-100)")
    if [ $jrc -eq 0 ] && [ $prc -eq 0 ]; then
      # R1: a header that ends "for" with nothing after it.
      grep -Eq '(^| )for *$' "$OUT/$tag.txt" && problems+=("header with a blank identifier")
      # R2: says there is nothing while the JSON carries data: any array or object
      # member other than links, ids and timestamps with at least one element.
      have=$(jq -r '[ (if type=="object" then to_entries[] else empty end)
                       | select(.key|test("^(_links|_entitlements|_pro_data|identifier|timestamp|state|title|aliases|descriptions|configurations|count|total|limit|offset|hasMore|schemaVersion|meta|note)$")|not)
                       | select(((.value|type)=="array" or (.value|type)=="object") and (.value|length)>0) ] | length' "$OUT/$tag.json" 2>/dev/null || echo 0)
      if [ "${have:-0}" -gt 0 ] && grep -Eqi '^ *(no [a-z -]+ (found|were returned)|none found)' "$OUT/$tag.txt"; then
        problems+=("pretty says nothing was found, JSON has $have populated section(s)")
      fi
      # R3: pretty output far smaller than the data behind it.
      # Descriptions, aliases and links pad the JSON without being what the command shows.
      jb=$(jq -c "del(.descriptions, .aliases, ._links, .configurations)" "$OUT/$tag.json" 2>/dev/null | wc -c)
      pl=$(wc -l <"$OUT/$tag.txt")
      if [ "$jb" -gt 4000 ] && [ "$pl" -lt 6 ]; then
        problems+=("pretty is $pl lines for $jb bytes of JSON")
      fi
    fi
    if [ ${#problems[@]} -gt 0 ]; then
      fail=$((fail + 1))
      printf 'FAIL  vdb %-22s %-22s %s\n' "$cmd" "$id" "$(IFS=';'; echo "${problems[*]}")"
    fi
  done
done
echo "vdbsmoke: $fail of $total command/vulnerability pairs have a problem"
[ $fail -eq 0 ]
