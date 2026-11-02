#!/usr/bin/env bash
# Keeps one config plan comment up to date on a pull request rather than adding
# one per push.
#
#   $1             the Markdown body (first line: <!-- vulnetix-config-plan -->)
#   GITHUB_TOKEN   needs pull-requests: write
#   VX_EVENT_NAME  the triggering event; anything but pull_request is a no-op
#
# A fork's read-only token cannot comment; the job summary still has the plan,
# so that is a warning, never a failure.
set -uo pipefail

body="$1"
if [ "${VX_EVENT_NAME:-}" != "pull_request" ] || [ -z "${GITHUB_TOKEN:-}" ] || [ -z "${GITHUB_EVENT_PATH:-}" ]; then
  exit 0
fi
pr="$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH")"
if [ -z "$pr" ]; then
  exit 0
fi

api="${GITHUB_API_URL:-https://api.github.com}/repos/$GITHUB_REPOSITORY/issues"
hdr=(-H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json")
payload="$(jq -Rs '{body: .}' "$body")"
existing="$(curl -fsS "${hdr[@]}" "$api/$pr/comments?per_page=100" |
  jq -r '[.[] | select(.body | startswith("<!-- vulnetix-config-plan -->"))][0].id // empty' || true)"
if [ -n "$existing" ]; then
  curl -fsS -X PATCH "${hdr[@]}" "$api/comments/$existing" -d "$payload" >/dev/null ||
    echo "::warning::could not update the config plan comment"
else
  curl -fsS -X POST "${hdr[@]}" "$api/$pr/comments" -d "$payload" >/dev/null ||
    echo "::warning::could not comment the config plan on the pull request"
fi
exit 0
