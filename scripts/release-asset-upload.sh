#!/usr/bin/env bash
# Upload files to a GitHub release, replacing an asset of the same name.
#
#   release-asset-upload.sh <owner/repo> <tag> <release-id or ""> <file>...
#
# Environment: GH_TOKEN (contents: write on the repository). QUOTA_WAIT_MAX
# (seconds, default 3900) bounds the total time spent waiting on rate limits.
#
# Why not `gh release upload <tag>`: gh looks the release up by tag over REST
# and as a draft over GraphQL at once, and since cli/cli#13723 it reports
# "release not found" when the REST lookup is refused for a spent quota and
# the GraphQL lookup finds no draft, which is every published release. The
# release workflows upload with a personal token whose 5,000 REST requests an
# hour everything else using it shares, so v4.24.8, v4.24.32 and v4.24.34
# failed that way and passed on a re-run once the quota had reset.
#
# So the release is resolved by id: the caller's, or GraphQL's (its own
# quota, which REST traffic does not spend). Every REST answer is classified:
# a spent quota waits for its reset, a secondary limit waits for Retry-After,
# a 404, 5xx or connection failure is retried a few times, anything else
# fails at once, and every failure names the HTTP status it got.
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: $0 <owner/repo> <tag> <release-id or \"\"> <file>..." >&2
  exit 2
fi
repo=$1 tag=$2 release_id=$3
shift 3
: "${GH_TOKEN:?GH_TOKEN is required}"
quota_wait_max=${QUOTA_WAIT_MAX:-3900}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
api_status=''
waited=0

header() {
  tr -d '\r' < "$tmp/head" | awk -v h="$1" \
    'index(tolower($0), h ":") == 1 { sub(/^[^:]*:[ \t]*/, ""); v = $0 } END { print v }'
}

# api METHOD URL [curl args...]: returns 0 on a 2xx, the body in $tmp/body.
api() {
  local method=$1 url=$2 attempt wait remaining reset retry
  shift 2
  for attempt in 1 2 3 4 5 6 7 8; do
    api_status=$(curl -sS -o "$tmp/body" -D "$tmp/head" -w '%{http_code}' \
      -X "$method" -H "Authorization: Bearer $GH_TOKEN" \
      -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
      "$@" "$url") || api_status=000
    case "$api_status" in 2??) return 0 ;; esac
    remaining=$(header x-ratelimit-remaining)
    reset=$(header x-ratelimit-reset)
    retry=$(header retry-after)
    if [[ $api_status =~ ^(403|429)$ && $remaining == 0 && -n $reset ]]; then
      wait=$((reset - $(date +%s) + 5))
      if ((wait < 5)); then wait=5; fi
      echo "::warning::$method $url: HTTP $api_status, the token's REST quota is spent until $(date -u -d "@$reset" +%H:%M:%SZ); waiting ${wait}s"
    elif [[ $api_status =~ ^(403|429)$ ]] && { [ -n "$retry" ] || grep -qi 'secondary rate limit' "$tmp/body"; }; then
      wait=${retry:-60}
      echo "::warning::$method $url: HTTP $api_status, secondary rate limit; waiting ${wait}s"
    elif [[ $api_status =~ ^(404|5..|000)$ ]] && ((attempt < 4)); then
      wait=$((attempt * 10))
      echo "$method $url: HTTP $api_status, retrying in ${wait}s"
    elif [ "$api_status" = 422 ]; then
      # The caller decides: on an upload it is an asset already there.
      echo "$method $url: HTTP 422: $(head -c 300 "$tmp/body")"
      return 1
    else
      echo "::error::$method $url: HTTP $api_status: $(head -c 500 "$tmp/body")"
      return 1
    fi
    if ((waited + wait > quota_wait_max)); then
      echo "::error::$method $url: still HTTP $api_status after waiting ${waited}s; re-run the job once the quota resets"
      return 1
    fi
    sleep "$wait"
    waited=$((waited + wait))
  done
  echo "::error::$method $url: HTTP $api_status after $attempt attempts"
  return 1
}

if [ -z "$release_id" ]; then
  for attempt in 1 2 3 4 5 6; do
    # shellcheck disable=SC2016 # $owner, $name and $tag are GraphQL variables
    release_id=$(gh api graphql \
      -f query='query($owner:String!,$name:String!,$tag:String!){repository(owner:$owner,name:$name){release(tagName:$tag){databaseId}}}' \
      -f owner="${repo%/*}" -f name="${repo#*/}" -f tag="$tag" \
      --jq '.data.repository.release.databaseId // empty') || release_id=''
    [ -n "$release_id" ] && break
    sleep $((attempt * 10))
  done
  if [ -z "$release_id" ]; then
    echo "::error::GraphQL has no release for $tag in $repo"
    exit 1
  fi
fi
echo "release $tag in $repo is id $release_id"

for file in "$@"; do
  name=$(basename "$file")
  upload="https://uploads.github.com/repos/$repo/releases/$release_id/assets?name=$name"
  if ! api POST "$upload" -H 'Content-Type: application/octet-stream' --data-binary "@$file"; then
    # 422 is an asset of that name already there (a re-run): replace it.
    if [ "$api_status" != 422 ]; then exit 1; fi
    echo "replacing the $name already on $tag"
    api GET "https://api.github.com/repos/$repo/releases/$release_id/assets?per_page=100"
    asset=$(jq -r --arg n "$name" '.[] | select(.name == $n) | .id' "$tmp/body")
    if [ -z "$asset" ]; then
      echo "::error::upload of $name refused with HTTP 422 and the release has no asset of that name to replace"
      exit 1
    fi
    api DELETE "https://api.github.com/repos/$repo/releases/assets/$asset"
    api POST "$upload" -H 'Content-Type: application/octet-stream' --data-binary "@$file"
  fi
  echo "uploaded $name to $tag"
done
