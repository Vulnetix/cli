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

## "404 Not Found" on a repository that plainly exists

A valid token is not the same thing as a token that can read *this* repository, and GitHub does
not let you tell the two apart. For a private repository your token was never granted, it answers
**404 Not Found**, not 403 Forbidden — confirming that a private repository exists would itself
leak something. So a perfectly good token produces a "not found" on a repository you are looking
straight at.

This bites fine-grained personal access tokens in particular: they only reach the repositories
listed under **Repository access**, and one created for a different repository will authenticate
happily and then see nothing here.

`analyze` checks for this before it scans anything, so you find out in the first second rather
than several minutes in. To fix it, either grant the token access to this repository (with read
access to Contents, Pull requests, Issues and Metadata), or use one that already has it:

```bash
gh auth refresh -s repo        # if you are using the gh CLI's token
export GITHUB_TOKEN=<token>    # a classic token with the `repo` scope
```

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
