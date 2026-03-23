---
name: release
description: Stage all changes, create a conventional commit (no co-author), push to main, wait for auto-version release, then run update-packages to update flake.nix/Homebrew/Scoop
argument-hint: [type] [scope] [description] — e.g., "feat vdb add ecosystem filtering" or "fix update"
---

# Release: Commit & Push to Main

Stage all changes, create a conventional commit without co-authoring, push to main, report what version bump will be triggered by the auto-version workflow, then run `just update-packages` to update package manager manifests (flake.nix, Homebrew, Scoop).

## Arguments

`$ARGUMENTS` should contain:
- **type** (required): `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`
- **scope** (optional): Component or area affected (e.g., `vdb`, `update`, `auth`, `upload`)
- **description** (optional): Brief hint for the commit subject — if omitted, derive from the diff

Examples:
- `/release feat update add self-update command`
- `/release fix vdb`
- `/release chore deps`

## Step 1 — Parse Arguments

Extract type, optional scope, and optional description from `$ARGUMENTS`:

```
TYPE = first word
SCOPE = second word (if it doesn't look like a description)
DESCRIPTION = remaining words
```

Validate type is one of: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`.

If invalid or missing, show usage and stop.

## Step 2 — Verify on Main Branch

```bash
BRANCH=$(git rev-parse --abbrev-ref HEAD)
```

If not on `main`:
```
Error: Must be on main branch to release (currently on '<branch>').

Switch with: git checkout main
```

## Step 3 — Check Working Tree

```bash
git status --porcelain
```

If no changes:
```
No changes to commit. Working directory is clean.
```

## Step 4 — Run Tests

```bash
just test
```

If tests fail, stop and report the failure. Do not commit broken code.

## Step 5 — Stage All Changes

```bash
git add -A
git status --short
```

Show the files that will be committed.

## Step 6 — Analyze Diff for Commit Message

```bash
git diff --cached --stat
git diff --cached
```

Write a conventional commit message based on the actual changes:

**Format:**
```
<type>[(scope)]: <subject>

[optional body — what and why, not how]
```

**Rules:**
- Subject: imperative mood, lowercase, no period, max 50 chars
- Body: wrap at 72 chars, explain what changed and why
- **NEVER** include a `Co-Authored-By` line

Use the description hint from arguments if provided, otherwise derive from the diff.

## Step 7 — Create Commit

```bash
git commit -m "$(cat <<'EOF'
<type>[(scope)]: <subject>

<optional body>
EOF
)"
```

**CRITICAL:** Do NOT include any `Co-Authored-By` line. No co-author. Ever.

Confirm:
```bash
git log -1 --oneline
```

## Step 8 — Push to Origin

```bash
git push origin main
```

## Step 9 — Report Release Outcome

After pushing, determine what the auto-version workflow will do:

```bash
LAST_TAG=$(git tag -l 'v*' --sort=-v:refname | head -n1)
```

Calculate the expected next version based on the commit type:
- `feat!:` or type with `!` → major bump
- `feat:` → minor bump
- everything else → patch bump

Report:

```
Pushed to main.

  Commit:   <hash> <type>[(scope)]: <subject>
  Files:    <N> changed

  Auto-version will bump: <patch|minor|major>
  Expected release:       <last tag> → <next version>

  Watch the release: gh run list -w auto-version.yml -L1
```

## Step 10 — Wait for Release and Update Packages

After reporting the release outcome, wait for the auto-version workflow to create the release, then update package manager manifests.

### Wait for the release

Poll the auto-version workflow until it completes:

```bash
# Wait for the workflow run triggered by our push
sleep 10
gh run list -w auto-version.yml -L1 --json status,conclusion,databaseId -q '.[0]'
```

Keep checking every 15 seconds until the workflow run completes (status == "completed"). If it takes longer than 5 minutes, warn the user but continue.

If the workflow conclusion is not "success", warn:
```
Warning: auto-version workflow did not succeed (conclusion: <conclusion>).
Skipping update-packages. Run manually: just update-packages
```

### Sync repos before updating

Before running update-packages, pull latest changes in this repo and sibling repos to avoid push rejections:

```bash
git pull --rebase origin main
```

Also pull sibling repos if they exist:
```bash
[ -d ../homebrew-tap ] && git -C ../homebrew-tap pull --rebase origin main
[ -d ../scoop-bucket ] && git -C ../scoop-bucket pull --rebase origin main
```

### Run update-packages

Once the release exists and repos are synced, run:

```bash
just update-packages
```

This updates flake.nix, Homebrew formula, and Scoop manifest with the new version and checksums, then commits and pushes each.

If `just update-packages` fails with a push rejection (`! [rejected]`, `fetch first`, `failed to push some refs`), pull and retry once:

```bash
git pull --rebase origin main && git push origin main
```

Do the same for sibling repos if their push was the one that failed.

Report what was updated:
```
Package manifests updated:
  flake.nix       → v<version>
  homebrew-tap    → v<version> (or "not found")
  scoop-bucket    → v<version> (or "not found")
```

If `just update-packages` fails for reasons other than a push rejection, report the error but do not fail the release — the commit and push already succeeded.

## Error Handling

### Not on Main
```
Error: Must be on main branch (currently on '<branch>').
```

### Tests Fail
```
Error: Tests failed. Fix before releasing.
```

### Push Rejected
```
Error: Push to main rejected.

Pull latest changes first:
  git pull --rebase origin main
```

### No Changes
```
No changes to commit. Nothing to release.
```
