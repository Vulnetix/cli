---
title: "Authentication"
weight: 1
description: "analyze needs GitHub credentials, checks for them before it starts, and stops if it cannot find any."
---

`vulnetix analyze` needs **GitHub credentials**, and it checks for them before it scans
anything.

## Why

Some of what `analyze` reports does not exist in the git repository at all:

- how long a pull request waited for its first review
- whether a merged pull request was ever approved by anybody other than its author
- whether a commit reached the default branch with no approving review — the single best
  compliance signal there is, and the one that catches a repository with immaculate review
  coverage on its pull requests and half its commits pushed straight to `main`
- how long issues sit unanswered

None of that is in the object database. It lives in the forge, and without credentials it
cannot be known.

## Why it fails at the start rather than the end

Because the alternative is worse. Without this check, you would wait five minutes for the scan,
and then get a report where a third of the metrics say `not measured` — and a report full of
nulls is the kind of thing people stop reading, which costs you the metrics that *were*
measured.

So the check runs first, makes exactly one API call, and either prints this:

```
GitHub authentication: ok (chrislangton via gh CLI, 4,987/5,000 requests remaining)
```

or stops, and tells you how to fix it.

The remaining-quota figure is there for a reason too. A token with twelve requests left will
not get through a scan, and you should find that out now.

## The three ways to authenticate

Resolved in this order. The first one found wins, and `analyze` tells you which it used.

### 1. `GITHUB_TOKEN`

**Already set for you inside GitHub Actions.** If you run `analyze` in CI, this works with no
configuration:

```yaml
- name: Analyze
  run: vulnetix analyze
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 2. `GH_TOKEN`

```bash
export GH_TOKEN=ghp_...
vulnetix analyze
```

### 3. The `gh` CLI

If neither variable is set, `analyze` asks the `gh` CLI for its own credentials:

```bash
gh auth login
vulnetix analyze
```

This works whether `gh` keeps its token in the system keyring or in a config file — we ask
`gh` rather than reading its files, because parsing another tool's storage format is a bug
waiting for the day that tool changes it.

## Token permissions

Read access to the repository's **pull requests**, **issues** and **contents**. The default
`GITHUB_TOKEN` in GitHub Actions already has this for the repository it is running in.

## Running without GitHub

### `--no-forge`

```bash
vulnetix analyze --no-forge
```

Skips the check, and skips the forge metrics. They are then reported as **`not measured`** with
a diagnostic explaining why — not as zero. The rest of the report (the graph, complexity,
coupling, dependencies, policy checks, secrets in history) is unaffected.

### Repositories that are not on GitHub

The check is **skipped automatically**. A GitLab repository does not fail for want of a GitHub
token; refusing to analyze a repository we were never going to call GitHub about would be a bug
wearing a security hat.

## Rate limits

`analyze` stops before your quota runs out, leaving headroom for the other steps in your CI job
that share the same token. If it stops early, the affected metric is marked **truncated**, with
the number of items it did not fetch and the reason:

```json
{
  "id": "security.commits.unreviewed",
  "value": 100,
  "evidenceCompleteness": "truncated",
  "omittedCount": 97,
  "truncationReason": "GitHub API rate limit reached; the remaining items were not fetched."
}
```

It does not fail the run and lose the work already done, and it does not sleep for an hour that
a CI job does not have. It reports what it got and declares what it did not — which is the only
one of those three options that leaves you able to trust the number.
