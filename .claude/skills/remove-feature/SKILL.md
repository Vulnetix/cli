---
name: remove-feature
description: Close PR, remove branch, delete worktree, and discard feature changes
disable-model-invocation: true
argument-hint: <pr-number|branch-name>
---

# Remove Feature Branch & Cleanup Worktree

Close a GitHub PR, remove the feature branch (local and remote), delete the associated git worktree, and clean up all references.

This is the inverse operation of the `new-feature` skill. Use this to clean up abandoned or completed feature branches that were created in worktrees.

## ⚠️ Safety Warning

This skill performs **destructive operations**:
- Closes the GitHub PR
- Deletes the local branch (unmerged changes will be lost)
- Deletes the remote branch on GitHub
- Removes the worktree directory from disk
- All uncommitted changes in the worktree will be lost

**Use this skill only when you're certain you want to discard the feature.**

## Steps

1. **Parse `$ARGUMENTS`**:
   - Argument can be either a **PR number** (e.g., `123`) or **branch name** (e.g., `fix-some-bug`)
   - Extract the first word from `$ARGUMENTS`

2. **Determine if argument is PR number or branch name**:
   ```bash
   ARG="$(echo "$ARGUMENTS" | awk '{print $1}')"

   if [[ "$ARG" =~ ^[0-9]+$ ]]; then
     # It's a PR number
     PR_NUMBER="$ARG"
     # Fetch branch name from PR
     BRANCH_NAME=$(gh pr view "$PR_NUMBER" --json headRefName --jq '.headRefName')
   else
     # It's a branch name
     BRANCH_NAME="$ARG"
     # Try to find associated PR (may not exist)
     PR_NUMBER=$(gh pr list --head "$BRANCH_NAME" --json number --jq '.[0].number' 2>/dev/null || echo "")
   fi
   ```

3. **Validate branch name exists**:
   ```bash
   if [ -z "$BRANCH_NAME" ]; then
     echo "Error: Could not determine branch name"
     exit 1
   fi

   echo "Branch: $BRANCH_NAME"
   [ -n "$PR_NUMBER" ] && echo "PR: #$PR_NUMBER"
   ```

4. **Determine worktree path** (same pattern as `new-feature`):
   ```bash
   REPO_NAME=$(basename "$(git rev-parse --show-toplevel)")
   WORKTREE_PATH="$(cd "$(git rev-parse --show-toplevel)/.." && pwd)/${REPO_NAME}-worktree-${BRANCH_NAME}"

   echo "Expected worktree path: $WORKTREE_PATH"
   ```

5. **Check if currently in the worktree being removed**:
   ```bash
   CURRENT_DIR="$(pwd)"
   IN_WORKTREE=false

   if [[ "$CURRENT_DIR" == "$WORKTREE_PATH"* ]]; then
     IN_WORKTREE=true
     echo "⚠️  Currently in worktree being removed. Switching to main repo..."
     cd "$(git rev-parse --show-toplevel)"
     echo "Switched to: $(pwd)"
   fi
   ```

6. **Close the GitHub PR** (if exists):
   ```bash
   if [ -n "$PR_NUMBER" ]; then
     echo "Closing PR #$PR_NUMBER..."
     gh pr close "$PR_NUMBER" --comment "Closing PR and removing feature branch." --delete-branch=false || {
       echo "⚠️  Failed to close PR (may already be closed)"
     }
   else
     echo "No PR found for branch $BRANCH_NAME"
   fi
   ```

7. **Remove the worktree** (force if necessary):
   ```bash
   if [ -d "$WORKTREE_PATH" ]; then
     echo "Removing worktree at $WORKTREE_PATH..."
     git worktree remove "$WORKTREE_PATH" 2>/dev/null || {
       echo "Worktree has uncommitted changes. Force removing..."
       git worktree remove --force "$WORKTREE_PATH"
     }
     echo "✓ Worktree removed"
   else
     echo "Worktree directory not found (may already be removed)"
   fi
   ```

8. **Delete the local branch** (force to handle unmerged changes):
   ```bash
   if git branch --list "$BRANCH_NAME" | grep -q "$BRANCH_NAME"; then
     echo "Deleting local branch $BRANCH_NAME..."
     git branch -D "$BRANCH_NAME" 2>/dev/null && echo "✓ Local branch deleted" || {
       echo "⚠️  Failed to delete local branch (may already be deleted)"
     }
   else
     echo "Local branch not found (may already be deleted)"
   fi
   ```

9. **Delete the remote branch**:
   ```bash
   if git ls-remote --exit-code --heads origin "$BRANCH_NAME" >/dev/null 2>&1; then
     echo "Deleting remote branch origin/$BRANCH_NAME..."
     git push origin --delete "$BRANCH_NAME" 2>/dev/null && echo "✓ Remote branch deleted" || {
       echo "⚠️  Failed to delete remote branch (may already be deleted)"
     }
   else
     echo "Remote branch not found (may already be deleted)"
   fi
   ```

10. **Clean up worktree references**:
    ```bash
    echo "Pruning worktree references..."
    git worktree prune
    echo "✓ Worktree references cleaned"
    ```

11. **Verify cleanup** and report status:
    ```bash
    echo ""
    echo "=== Cleanup Summary ==="
    echo "Branch: $BRANCH_NAME"
    [ -n "$PR_NUMBER" ] && echo "PR #$PR_NUMBER: Closed"
    echo "Worktree: Removed from $WORKTREE_PATH"
    echo "Local branch: Deleted"
    echo "Remote branch: Deleted"
    echo ""
    echo "✓ Feature cleanup complete"

    # Show remaining worktrees
    echo ""
    echo "Remaining worktrees:"
    git worktree list
    ```

## Important Notes

### Automatic Directory Switching
If you run this skill while inside the worktree being removed, the skill will automatically switch you back to the main repository directory before performing cleanup. This prevents errors from removing the current working directory.

### Graceful Failure Handling
Each cleanup step handles missing resources gracefully:
- If the PR is already closed, it skips PR closure
- If the branch is already deleted, it skips branch deletion
- If the worktree doesn't exist, it skips worktree removal
- The skill will complete successfully even if some resources are already gone

### Force Operations
The skill uses force flags to ensure cleanup succeeds:
- `git worktree remove --force` - Removes worktree even with uncommitted changes
- `git branch -D` - Force deletes branch even if unmerged
- These are appropriate since the goal is to discard all changes

### Verification After Cleanup
After running this skill, verify cleanup with:
```bash
git worktree list        # Should not show the removed worktree
git branch -a            # Should not show the removed branch
ls ../                   # Should not show the worktree directory
```

## Common Scenarios

### Remove by PR Number
```
/remove-feature 123
```
Fetches branch name from PR #123, then removes everything.

### Remove by Branch Name
```
/remove-feature fix-some-bug
```
Finds the associated PR (if exists), then removes everything.

### Remove While in Worktree
If you're currently in the worktree directory:
```
cd /path/to/saas-worktree-my-feature
/remove-feature my-feature
```
The skill automatically switches back to the main repo before cleanup.

### Already-Deleted Resources
If some resources are already gone:
```
/remove-feature old-branch
```
The skill handles missing resources gracefully and reports what was found vs. what was already gone.
