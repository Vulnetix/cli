#!/usr/bin/env bash
# config-plan and config-apply: Platform IaC through the config engine.
#
#   $1                     config-plan or config-apply
#   VULNETIX_CONFIG_TOKEN  read by the CLI itself, never placed on argv
#   VX_IN_CONFIG_PATH      documents, one file or directory per line
#   VX_IN_CONFIG_MANAGER   --manager
#   VX_IN_CONFIG_PRUNE     true: --prune
#   VX_IN_VALIDATE_ONLY    true (config-plan): validate offline, no engine call
#   VX_RESULT_FILE         where result= and summary= are left for run.sh
#
# Exits with the CLI's code: 0 success, 3 blocked, anything else a failure.
set -uo pipefail

lib="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
task="$1"
result_file="${VX_RESULT_FILE:-/dev/null}"
tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
summary_md="${GITHUB_STEP_SUMMARY:-/dev/null}"

cfg=()
while IFS= read -r f; do
  f="${f#"${f%%[![:space:]]*}"}"
  f="${f%"${f##*[![:space:]]}"}"
  if [ -n "$f" ]; then cfg+=(-f "$f"); fi
done <<<"${VX_IN_CONFIG_PATH:-}"

if [ "$task" = "config-plan" ] && [ "${VX_IN_VALIDATE_ONLY:-}" = "true" ]; then
  vulnetix config validate "${cfg[@]}"
  code=$?
  if [ "$code" = 0 ]; then
    printf 'result=success\nsummary=Config documents are valid\n' >"$result_file"
  else
    printf 'result=failure\nsummary=Config documents are not valid\n' >"$result_file"
  fi
  exit "$code"
fi

if [ -n "${VX_IN_CONFIG_MANAGER:-}" ]; then cfg+=(--manager "$VX_IN_CONFIG_MANAGER"); fi
if [ "${VX_IN_CONFIG_PRUNE:-}" = "true" ]; then cfg+=(--prune); fi

if [ "$task" = "config-apply" ]; then
  vulnetix config apply --auto-approve "${cfg[@]}" | tee "$tmp/vulnetix-apply.txt"
  code=${PIPESTATUS[0]}
  {
    echo "### Vulnetix config apply"
    echo
    echo '```'
    cat "$tmp/vulnetix-apply.txt"
    echo '```'
  } >>"$summary_md"
  case "$code" in
  0) printf 'result=success\nsummary=Config applied\n' >"$result_file" ;;
  3) printf 'result=blocked\nsummary=Config plan has blocking conditions; nothing applied\n' >"$result_file" ;;
  *) printf 'result=failure\nsummary=Config apply failed\n' >"$result_file" ;;
  esac
  exit "$code"
fi

plan="$tmp/vulnetix-plan.json"
vulnetix config plan -o json "${cfg[@]}" >"$plan"
code=$?
if ! jq -e .planHash "$plan" >/dev/null 2>&1; then
  # No plan came back (usage error, auth, network); the CLI has already said
  # why on stderr.
  printf 'result=failure\nsummary=Config plan failed\n' >"$result_file"
  exit "$code"
fi

body="$tmp/vulnetix-plan.md"
jq -r '
  def cell: tostring | gsub("\\|"; "\\|") | gsub("\n"; " ");
  def mark: {create: "+", update: "~", delete: "-", noop: "="}[.] // "?";
  "<!-- vulnetix-config-plan -->",
  "### Vulnetix config plan",
  "",
  "Manager `\(.manager)`, prune \(if .prune then "on" else "off" end), plan hash `\(.planHash)`",
  "",
  "| | Object | Action | Changes |",
  "|---|---|---|---|",
  (.items[] | "| \(.action | mark) | `\(.kind)/\(.name)` | \(.action)\(if .adopt then " (adopt)" else "" end)\(if .drift then " (drift)" else "" end) | \([.changes[] | "`\(.path)`: \(.from | tojson | cell) -> \(.to | tojson | cell)"] | join("<br>")) |"),
  (if (.blocking | length) > 0 then "", "**Blocking: this plan cannot be applied**", "", (.blocking[] | "- `\(.code)` \(if .kind then "`\(.kind)/\(.name)` " else "" end)\(.message)") else empty end),
  (if (.warnings | length) > 0 then "", "**Warnings**", "", (.warnings[] | "- `\(.code)` \(.message)") else empty end),
  "",
  "\(.summary.create) to create, \(.summary.update) to update, \(.summary.delete) to delete, \(.summary.noop) unchanged"
' "$plan" >"$body"
cat "$body" >>"$summary_md"

bash "$lib/config-plan-comment.sh" "$body"

counts="$(jq -r '"\(.summary.create) to create, \(.summary.update) to update, \(.summary.delete) to delete, \(.summary.noop) unchanged"' "$plan")"
case "$code" in
0) printf 'result=success\nsummary=%s\n' "$counts" >"$result_file" ;;
3) printf 'result=blocked\nsummary=%s\n' "$counts" >"$result_file" ;;
*) printf 'result=failure\nsummary=%s\n' "$counts" >"$result_file" ;;
esac
exit "$code"
