#!/usr/bin/env bash
# Runs `vulnetix analyze` against a git worktree, in the layout that crashed it.
#
# A repository checked out as a worktree differs from a clone in two ways that
# matter here: `.git` is a file pointing at the real gitdir rather than a
# directory, and the tree usually lives under a path such as
# `.claude/worktrees/<name>` that is itself inside another checkout. Both reach
# `analyze`: the history walk, the file walker and the evidence-record ids
# derived from file paths.
#
# The fixture is two files whose paths differ only in punctuation. Evidence
# record ids are built from a sanitised form of the path, so these two used to
# collapse to one id and abort the run with "duplicate evidence record id".
#
# Usage: scripts/ci-worktree-analyze.sh <path-to-vulnetix-binary>
set -euo pipefail

bin=$(realpath "${1:?usage: $0 <vulnetix-binary>}")
root=$(git rev-parse --show-toplevel)
name="ci-analyze-$$"
wt="$root/.claude/worktrees/$name"
out=$(mktemp -d)

cleanup() {
  git -C "$root" worktree remove --force "$wt" 2>/dev/null || true
  git -C "$root" worktree prune
  rm -rf "$out"
}
trap cleanup EXIT

mkdir -p "$root/.claude/worktrees"
git -C "$root" worktree add --detach "$wt" HEAD >/dev/null

# The property the rest of the script depends on: a worktree's .git is a file.
if [ ! -f "$wt/.git" ]; then
  echo "::error::expected $wt/.git to be a file; this is not testing a worktree" >&2
  exit 1
fi

mkdir -p "$wt/collide/a"
for f in "$wt/collide/a/m.js" "$wt/collide/a-m.js"; do
  cat >"$f" <<'JS'
function _t() { return 1; }
function e() { return _t(); }
module.exports = { e };
JS
done

run() {
  local label=$1 path=$2 report=$3
  echo "::group::analyze ($label)"
  "$bin" analyze --path "$path" --no-upload --no-forge --silent \
    --output-file "$report" -o json >"$out/$label.stdout" 2>"$out/$label.stderr" || {
    echo "::error::analyze exited non-zero ($label)" >&2
    cat "$out/$label.stderr" >&2
    echo "::endgroup::"
    exit 1
  }
  if grep -q "^panic:\|goroutine " "$out/$label.stderr"; then
    echo "::error::analyze panicked ($label)" >&2
    cat "$out/$label.stderr" >&2
    echo "::endgroup::"
    exit 1
  fi
  test -s "$report" || { echo "::error::no report written ($label)" >&2; exit 1; }
  echo "ok: $report ($(wc -c <"$report") bytes)"
  echo "::endgroup::"
}

# From inside the worktree, where .git is a file.
run in-worktree "$wt" "$out/in-worktree.json"

# From the checkout that contains the worktree (the reporter's layout), where
# the worktree's files are walked as part of the parent.
run from-parent "$root" "$out/from-parent.json"

echo "worktree analyze: ok"
