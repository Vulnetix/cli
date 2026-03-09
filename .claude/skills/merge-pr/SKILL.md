---
name: merge-pr
description: Check PR for current branch, update with session todos, approve and merge if complete, or comment with remaining work
argument-hint: [--force to merge even with remaining tasks]
---

# Merge PR with Session Todos

Check the pull request for the current branch, update its description with Claude session todos, and either approve and merge (if all work is complete) or comment with remaining tasks.

## Arguments

`$ARGUMENTS` can include:
- `--force` — Approve and merge even if there are pending todos (use with caution)

## Step 1 — Get Current Branch and PR

```bash
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "Current branch: $BRANCH"
```

Check if a PR exists for this branch targeting main:

```bash
gh pr list --head "$BRANCH" --base main --json number,title,state,url
```

If no PR is found, report: "No open PR found for branch `$BRANCH` targeting `main`."

If a PR is found, store the PR number for later steps.

## Step 2 — Collect Session Todos

Get all todos from the current session using the TaskList tool. This provides:
- Task subject (title)
- Task status (pending, in_progress, completed)
- Task description (details)

## Step 3 — Format Todos as Markdown

Create a markdown summary of todos in this format:

```markdown
## Claude Session Tasks

### Completed ✅
- [x] Task subject 1
- [x] Task subject 2

### In Progress 🔄
- [ ] Task subject 3

### Pending ⏳
- [ ] Task subject 4
- [ ] Task subject 5
```

Group tasks by status (completed, in_progress, pending). If there are no tasks in a category, omit that section.

## Step 4 — Get Current PR Description

```bash
gh pr view "$PR_NUMBER" --json body --jq '.body'
```

## Step 5 — Update PR Description

Append the todo list to the PR description (or replace an existing "Claude Session Tasks" section if present):

```bash
gh pr edit "$PR_NUMBER" --body "$(cat <<'EOF'
[Original PR description]

---

## Claude Session Tasks

[Formatted todos from Step 3]

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

## Step 6 — Determine Action

Count pending and in-progress tasks:
- If **all tasks are completed** (or `--force` flag is used):
  - Proceed to **Step 7 (Approve and Merge)**
- If **any tasks remain pending or in progress**:
  - Proceed to **Step 8 (Comment with Remaining Work)**

## Step 7 — Approve and Merge (All Complete)

Create an approval review:

```bash
gh pr review "$PR_NUMBER" --approve --body "✅ All Claude session tasks completed. Approving and merging.

$(cat <<'EOF'
All tracked tasks have been completed. This PR is ready to merge.

🤖 Approved by Claude Code
EOF
)"
```

Merge the PR:

```bash
gh pr merge "$PR_NUMBER" --squash --delete-branch
```

After successful merge, proceed to **Step 7.5 (Local Cleanup)**.

## Step 7.5 — Local Cleanup (After Successful Merge)

After the PR is merged, clean up the local environment:

```bash
# Switch to main branch
git checkout main

# Pull latest changes (includes the merged PR)
git pull origin main

# Delete the local feature branch
git branch -d "$BRANCH"
```

If the local branch deletion fails (uncommitted changes or unmerged work), use:

```bash
# Force delete (use with caution - only after confirming merge succeeded)
git branch -D "$BRANCH"
```

Report cleanup success:
```
✅ Local cleanup completed
   • Switched to main branch
   • Pulled latest changes
   • Deleted local branch: $BRANCH
```

## Step 8 — Comment with Remaining Work (Incomplete)

Add a comment listing remaining tasks:

```bash
gh pr comment "$PR_NUMBER" --body "$(cat <<'EOF'
## 🔄 Work In Progress

The following tasks are still pending:

### In Progress
- Task X
- Task Y

### Pending
- Task A
- Task B

Please complete these tasks before merging.

🤖 Comment by Claude Code
EOF
)"
```

Report summary:
```
⏸️ PR #$PR_NUMBER updated with remaining work
   ✅ Completed: N tasks
   🔄 In Progress: M tasks
   ⏳ Pending: P tasks

   Review: [PR URL]
```

## Step 9 — Final Summary

Always output a final summary:

```
╔═══════════════════════════════════════════════════╗
║             PR MERGE STATUS                       ║
╚═══════════════════════════════════════════════════╝

BRANCH:        fix-dashboard-compliance-all-contexts
PR NUMBER:     #123
PR TITLE:      Fix dashboard compliance component
STATUS:        ✅ MERGED (or ⏸️ AWAITING COMPLETION)

TASKS SUMMARY:
  ✅ Completed:    5
  🔄 In Progress:  0
  ⏳ Pending:      0

ACTION TAKEN:    Approved and merged (or Added comment with remaining work)
PR URL:          https://github.com/org/repo/pull/123

LOCAL STATE:
  Current branch:  main
  Remote deleted:  ✅ Yes
  Local deleted:   ✅ Yes
  Latest pulled:   ✅ Yes
```

## Error Handling

### No PR Found
If no PR exists for the current branch:
```
❌ No open PR found for branch '$BRANCH' targeting 'main'

Options:
1. Create a PR first using: gh pr create --base main
2. Check if you're on the correct branch: git branch
3. Verify the PR hasn't already been merged: gh pr list --state merged
```

### PR Already Merged
If the PR is already merged:
```
ℹ️ PR #$PR_NUMBER is already merged
   No action needed
```

### No Tasks Found
If there are no session todos:
```
ℹ️ No Claude session tasks found

The PR can be reviewed and merged manually, or you can:
1. Create tasks using the TaskCreate tool
2. Run this command again after creating tasks
```

## Safety Notes

- **Always review the PR changes** before merging
- The `--force` flag bypasses completion checks — use only when you're certain
- This skill does NOT run tests — ensure CI passes before merging
- Deleted branches cannot be recovered — ensure all work is pushed
- **After successful merge**, the skill will:
  - Switch your local branch to `main`
  - Pull latest changes from `origin/main`
  - Delete the local feature branch (both remote and local)
- If you have uncommitted changes, commit or stash them before running this skill

## Usage Examples

```bash
# Standard flow: update PR with todos, approve and merge if complete
/merge-pr

# Force merge even with pending tasks (use with caution)
/merge-pr --force

# Complete workflow on a feature branch with open PR
/merge-pr
# → Updates PR description with session todos
# → Approves and merges if all tasks completed
# → Switches to main branch
# → Pulls latest changes
# → Deletes local feature branch
# OR
# → Comments with remaining work if tasks are incomplete
```
