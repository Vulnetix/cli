---
name: new-feature
description: Create a feature branch in a git worktree, open a draft PR, then enter plan mode to investigate and populate the PR
disable-model-invocation: true
argument-hint: <branch-name> [PR title]
---

# New Feature Branch & Draft PR (Worktree)

Create a feature branch in a **git worktree** from `main`, open a draft PR targeting `main`, then enter plan mode to investigate and build a proper implementation plan.

The worktree approach keeps the current branch untouched and creates a separate working directory for the new feature.

## Steps

1. Parse `$ARGUMENTS`:
   - First word → **branch name**
   - Remaining words → **PR title** (if none provided, humanize the branch name by replacing hyphens with spaces and capitalizing)

2. Fetch latest main and determine repo name:
   ```bash
   git fetch origin main
   ```
   Determine the repo name from the git root directory (e.g. `basename $(git rev-parse --show-toplevel)` → `saas`). Use this to prefix the worktree directory: `<repo>-worktree-<branch-name>`. Resolve the **absolute path** of the worktree: `WORKTREE_PATH="$(cd "$(git rev-parse --show-toplevel)/.." && pwd)/<repo>-worktree-<branch-name>"`.

3. Create a worktree with the new branch based on `origin/main`. Worktrees live as siblings to the repo root:
   ```bash
   git worktree add "$WORKTREE_PATH" -b <branch-name> origin/main
   ```

4. Symlink `node_modules` from the main repo to avoid redundant dependency installation:
   ```bash
   REPO_ROOT="$(git rev-parse --show-toplevel)"
   if [ -d "$REPO_ROOT/node_modules" ]; then
     ln -s "$REPO_ROOT/node_modules" "$WORKTREE_PATH/node_modules"
     echo "✓ Symlinked node_modules from main repo"
   else
     echo "⚠ No node_modules found in main repo. You may need to run npm install in the worktree."
   fi

   # Symlink environment files from the original repo
   for f in .dev.vars .env; do
     if [ -f "$REPO_ROOT/$f" ]; then
       ln -s "$REPO_ROOT/$f" "$WORKTREE_PATH/$f"
       echo "✓ Symlinked $f from main repo"
     fi
   done
   ```

5. **CRITICAL — Switch the session to the worktree directory.** All subsequent commands, file reads, edits, globs, and greps **MUST** use the worktree absolute path. From this point forward, use `$WORKTREE_PATH` as the base for every tool call:
   - Bash: prefix all commands with `cd "$WORKTREE_PATH" &&` (working directory does not persist across tool calls reliably)
   - Read / Edit / Write: use `$WORKTREE_PATH/...` absolute paths
   - Glob / Grep: set the `path` parameter to `$WORKTREE_PATH`

6. Create an empty initial commit and push:
   ```bash
   cd "$WORKTREE_PATH" && git commit --allow-empty -m "chore: initialize <branch-name>" && git push -u origin <branch-name>
   ```

7. Open a draft PR targeting `main`:
   ```bash
   cd "$WORKTREE_PATH" && gh pr create --base main --title "<title>" --body "$(cat <<'EOF'
   ## Summary
   - Initial branch setup for <title>

   ## Test plan
   - [ ] TODO

   🤖 Generated with [Claude Code](https://claude.com/claude-code)
   EOF
   )" --draft
   ```

8. Report the PR URL and worktree path back to the user. Remind them that this session is now operating in the worktree at `$WORKTREE_PATH`.

9. Enter plan mode using `EnterPlanMode` to:
   - Investigate the codebase **in the worktree directory** to understand the problem/feature described in the PR title
   - Identify relevant files, components, and dependencies
   - Design an implementation approach
   - Build a concrete task list with test plan items
   - **All file exploration must use `$WORKTREE_PATH` as the root**

10. After the plan is approved, update the draft PR body with `gh pr edit` to replace the TODO placeholders with the actual plan:
   ```bash
   cd "$WORKTREE_PATH" && gh pr edit <pr-number> --body "$(cat <<'EOF'
   ## Summary
   <bullet points from the plan describing what will change>

   ## Test plan
   <checklist items derived from the plan>

   🤖 Generated with [Claude Code](https://claude.com/claude-code)
   EOF
   )"
   ```

11. Proceed with implementation **inside the worktree**. All code changes happen at `$WORKTREE_PATH`, never in the original repo directory.

## Important: Session Directory Binding

After step 5, this Claude session is bound to the worktree directory. **Never** fall back to the original repo path for any operation. If you need to reference the original repo (e.g. to compare), do so explicitly and return to `$WORKTREE_PATH` immediately.

## Worktree Cleanup

When the feature is complete and merged, use the `remove-feature` skill:
```
/remove-feature <pr-number|branch-name>
```

Or manually remove the worktree:
```bash
git worktree remove "$WORKTREE_PATH"
git branch -d <branch-name>
```
