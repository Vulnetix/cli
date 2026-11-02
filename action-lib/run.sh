#!/usr/bin/env bash
# Runs one Vulnetix CLI command for a composite action.
#
# Every input arrives as an environment variable (VX_*, VX_IN_*, and the
# VULNETIX_* credentials, which the CLI reads itself). The command is built as
# an argv array and run directly: nothing is passed through eval, and no
# ${{ }} expression is interpolated into this script.
#
#   VX_ACTION            the action (sca, sast, upload, ...) or the root task
#   VX_PATH              --path for commands that take one
#   VX_ARGS              extra arguments, split on whitespace
#   VX_CODE_SCANNING     true: scan-family commands publish to code scanning
#   VX_DEPENDENCY_GRAPH  true: scan-family commands submit the SBOM
#
# Outputs: files, sarif, sbom, manifest, exit-code, result, summary. The step
# itself exits 0 when the command ran; finish.sh re-raises its exit code.
set -uo pipefail

lib="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=action-lib/commands.sh
. "$lib/commands.sh"

action="${VX_ACTION:-info}"
# The root action's original task name for gha upload.
if [ "$action" = "gha" ]; then action=gha-upload; fi
out="${GITHUB_OUTPUT:-/dev/null}"

# One manifest per step, so the outputs list only what this step wrote.
if [ -z "${VULNETIX_ARTIFACT_MANIFEST:-}" ]; then
  VULNETIX_ARTIFACT_MANIFEST="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/vulnetix-${action}-${GITHUB_ACTION:-$$}.jsonl"
fi
export VULNETIX_ARTIFACT_MANIFEST
: >"$VULNETIX_ARTIFACT_MANIFEST"
VX_RESULT_FILE="${VULNETIX_ARTIFACT_MANIFEST%.jsonl}.result"
export VX_RESULT_FILE
: >"$VX_RESULT_FILE"

case "$action" in
config-plan | config-apply)
  bash "$lib/config.sh" "$action"
  code=$?
  ;;
github-publish)
  bash "$lib/publish.sh"
  code=$?
  ;;
info | "")
  vulnetix
  code=$?
  ;;
*)
  if ! vx_build "$action"; then
    echo "::error::unknown Vulnetix action or task: $action"
    exit 2
  fi
  if [ "$vx_takes_path" = true ]; then
    cmd+=(--path "${VX_PATH:-.}")
  fi
  if [ "$vx_scan" = true ]; then
    targets=()
    [ "${VX_CODE_SCANNING:-}" = "true" ] && targets+=(code-scanning)
    [ "${VX_DEPENDENCY_GRAPH:-}" = "true" ] && targets+=(dependency-graph)
    if [ "${#targets[@]}" -gt 0 ]; then
      cmd+=(--github-publish "$(
        IFS=,
        echo "${targets[*]}"
      )")
    fi
  fi
  if [ -n "${VX_ARGS:-}" ]; then
    # Word splitting only; globbing is off so a * stays an argument.
    set -f
    # shellcheck disable=SC2206
    extra=(${VX_ARGS})
    set +f
    cmd+=("${extra[@]}")
  fi
  echo "vulnetix ${cmd[*]}"
  if [ "$action" = "upload" ]; then
    result_json="$(vulnetix "${cmd[@]}")"
    code=$?
    printf '%s\n' "$result_json"
    uuid="$(printf '%s' "$result_json" | jq -r '.pipelineRecord.uuid // empty' 2>/dev/null || true)"
    [ -n "$uuid" ] && echo "upload-uuid=$uuid" >>"$out"
  else
    vulnetix "${cmd[@]}"
    code=$?
  fi
  ;;
esac

# What the command wrote, from the manifest: the last entry per path, for
# files that still exist.
files=""
sarif=""
sbom=""
if [ -s "$VULNETIX_ARTIFACT_MANIFEST" ] && command -v jq >/dev/null 2>&1; then
  entries="$(jq -rs 'group_by(.path) | map(last) | .[] | [.kind, .path] | @tsv' "$VULNETIX_ARTIFACT_MANIFEST" 2>/dev/null || true)"
  while IFS=$'\t' read -r kind path; do
    if [ -z "$path" ] || [ ! -f "$path" ]; then continue; fi
    files+="$path"$'\n'
    case "$kind" in
    sarif) sarif+="$path"$'\n' ;;
    cyclonedx)
      case "$path" in
      *sbom.cdx.json) sbom="$path" ;;
      *) [ -z "$sbom" ] && [ "$action" = "sbom" ] && sbom="$path" ;;
      esac
      ;;
    esac
  done <<<"$entries"
fi

# Multi-line outputs use the heredoc form with a random delimiter.
delim="vx_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
{
  echo "files<<$delim"
  printf '%s' "$files"
  echo "$delim"
  echo "sarif<<$delim"
  printf '%s' "$sarif"
  echo "$delim"
  echo "sbom=$sbom"
  echo "manifest=$VULNETIX_ARTIFACT_MANIFEST"
  echo "exit-code=$code"
  # A script that knows better (config.sh: blocked, the plan's counts) leaves
  # its result and summary in VX_RESULT_FILE.
  if [ -s "$VX_RESULT_FILE" ]; then
    cat "$VX_RESULT_FILE"
  else
    if [ "$code" = 0 ]; then
      echo "result=success"
    else
      echo "result=failure"
    fi
    echo "summary=vulnetix $action exited $code"
  fi
} >>"$out"

# The credentials only ever travel as environment variables; if a credentials
# file appears in the workspace, something stored one, and an artifact upload
# could ship it.
if [ -f "${VX_PATH:-.}/.vulnetix/credentials.json" ] || [ -f .vulnetix/credentials.json ]; then
  echo "::warning::a .vulnetix/credentials.json exists in the workspace; do not upload it as an artifact"
fi
exit 0
