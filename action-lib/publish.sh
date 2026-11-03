#!/usr/bin/env bash
# Publishes into GitHub after a command that does not publish itself (license,
# sbom), and for the github-publish action.
#
#   VX_CODE_SCANNING     true: vulnetix gha publish code-scanning
#   VX_DEPENDENCY_GRAPH  true: vulnetix gha publish dependency-graph
#   VX_IN_CAMPAIGNS      true: vulnetix gha publish campaigns (github-publish
#                        only), with VX_IN_CAMPAIGNS_ORG, _RECREATE, _DRY_RUN
#                        and _GITHUB_TOKEN
#   VX_PATH              the repository root (default .)
#   VX_MANIFEST          the run step's artifact manifest: its SARIF and SBOM
#                        are what gets published
#   VX_IN_SARIF          explicit SARIF files, one per line (github-publish)
#   VX_IN_SBOM           explicit SBOM (github-publish)
#   GITHUB_TOKEN         read by the CLI
#
# A failure is a warning: publishing to GitHub never fails the scan, and a
# fork's pull request has a read-only token.
set -uo pipefail

root="${VX_PATH:-.}"
status=0

manifest_paths() {
  # $1: kind. Paths of that kind in the manifest, last entry per path.
  if [ -n "${VX_MANIFEST:-}" ] && [ -s "$VX_MANIFEST" ]; then
    jq -rs --arg k "$1" 'group_by(.path) | map(last) | .[] | select(.kind == $k) | .path' "$VX_MANIFEST" 2>/dev/null || true
  fi
}

if [ "${VX_CODE_SCANNING:-}" = "true" ]; then
  args=(gha publish code-scanning --path "$root")
  while IFS= read -r f; do
    f="${f#"${f%%[![:space:]]*}"}"
    f="${f%"${f##*[![:space:]]}"}"
    case "$f" in
    "" | */code-scanning/*) ;;
    *) args+=(--sarif "$f") ;;
    esac
  done <<<"${VX_IN_SARIF:-}$(printf '\n')$(manifest_paths sarif)"
  if ! vulnetix "${args[@]}"; then
    echo "::warning::GitHub code scanning upload failed; see the log above"
    status=1
  fi
fi

if [ "${VX_DEPENDENCY_GRAPH:-}" = "true" ]; then
  args=(gha publish dependency-graph --path "$root")
  sbom="${VX_IN_SBOM:-}"
  if [ -z "$sbom" ]; then
    sbom="$(manifest_paths cyclonedx | grep -E 'sbom\.cdx\.json$|\.cdx\.json$' | head -n1 || true)"
  fi
  if [ -n "$sbom" ]; then args+=(--sbom "$sbom"); fi
  if ! vulnetix "${args[@]}"; then
    echo "::warning::GitHub dependency graph submission failed; see the log above"
    status=1
  fi
fi

if [ "${VX_IN_CAMPAIGNS:-}" = "true" ]; then
  args=(gha publish campaigns)
  if [ -n "${VX_IN_CAMPAIGNS_ORG:-}" ]; then args+=(--org "$VX_IN_CAMPAIGNS_ORG"); fi
  if [ "${VX_IN_CAMPAIGNS_RECREATE:-}" = "true" ]; then args+=(--recreate-on-scope-change); fi
  if [ "${VX_IN_CAMPAIGNS_DRY_RUN:-}" = "true" ]; then args+=(--dry-run); fi
  # Campaigns need an organization owner's or security manager's token; the
  # workflow token cannot manage them. VULNETIX_API_KEY and VULNETIX_ORG_ID (or
  # VULNETIX_API_TOKEN), the Vulnetix side, are already in the environment.
  if ! GITHUB_TOKEN="${VX_IN_CAMPAIGNS_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}" vulnetix "${args[@]}"; then
    echo "::warning::GitHub security campaigns failed; see the log above"
    status=1
  fi
fi

# The github-publish action reports its own status; after another command a
# publish failure stays a warning.
if [ "${VX_ACTION:-}" = "github-publish" ]; then
  exit "$status"
fi
exit 0
