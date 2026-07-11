---
title: "Analyze"
weight: 10
description: "Build the org's tech-stack graph and report evidence-backed repository metrics — where every number opens into the things that produced it."
---

The `vulnetix analyze` command does two things over one repository.

**It builds a graph of the org's tech stack.** Nodes and edges inside the repository, plus the
**cross-repo join keys** that other repositories' graphs match against. The scan never reads a
second repository — it publishes what this one *provides* and what it *consumes*, and the
server forms an edge wherever one repo's consumes meets another's provides. Run it in every
repository's CI and you get the whole org's picture, without any repository needing access to
any other.

**It reports metrics, each carrying the evidence that produced it.** Business intelligence,
security, quality, maintainability, trustworthiness, activity.

## The rule that governs everything here

> **If a metric's value is 23, the report contains 23 evidence records.**
>
> A metric that hit a cap says how many items it dropped, and why. A metric that could not be
> measured is `null` — never zero.

That last distinction is the one most tools lose, and it is the one that matters most. "We
found no unreviewed commits" and "we could not check whether commits were reviewed" are
different claims. A report that cannot tell them apart will eventually be used to say
something untrue, and the person reading it will have no way to know.

So a collector that could not run does not quietly contribute zeros. It contributes nulls, and
a diagnostic saying why:

```
Stale dependencies        not measured    —
```

## What you need before running it

**GitHub credentials.** Review coverage, pull-request response times, and whether commits
reached the default branch unreviewed do not exist in the git repository — they live in the
forge. `analyze` checks for credentials *before it starts scanning* and stops if it cannot
find any, rather than working for five minutes and handing you a report where a third of the
numbers are null.

See [Authentication](authentication/). In GitHub Actions it already works, with no
configuration.

## What it produces

```bash
vulnetix analyze
```

- `.vulnetix/analyze.report.json` — the report, validated against
  [the schema](https://vulnetix.com/schemas/vulnetix-analyze-report.schema.json) before it is
  written. A report we would reject on the way in is one we cannot produce on the way out.
- A summary in the terminal, grouped by metric family.
- An upload to `/v2/cli.insights` when you are authenticated to Vulnetix, which is what feeds
  the org graph at **/vdb-graph** in the console. Uploads are best-effort: if the network
  fails, the report on disk is still authoritative and the command still succeeds.

## The graph

| Node kinds | |
|---|---|
| **Code** | `file`, `function`, `method`, `class`, `interface` |
| **Supply chain** | `dependency`, `package`, `container_image` |
| **Service surface** | `route`, `topic`, `workflow`, `service` |
| **People** | `contributor` |

| Edge kinds | |
|---|---|
| `contains` | a file contains a symbol; the repo contains a file |
| `imports` | a file imports another file **in this repository** — resolved exactly, never guessed |
| `depends_on` | the repository depends on a package |
| `authored` | a contributor authored commits |
| `couples_with` | two files keep changing in the same commit — *derived from history, not from the code* |

`couples_with` is the one edge a careful reader of the source could not have drawn themselves.
Two files in different packages with no import between them, that nonetheless change together
eighty percent of the time, are coupled — and nothing in the code says so.

### Cross-repo join keys

This is what makes it an *org* graph rather than a dependency graph.

| Join kind | Provided when | Consumed when |
|---|---|---|
| `package` | the repo declares a module (`go.mod`, `package.json`) | the repo depends on it |
| `http_route` | a file stands up a router and declares the route | *not yet detected — see below* |
| `topic` | a publish call names it | a subscribe call names it |
| `container_image` | — | a `FROM` or a compose `image:` names it |
| `workflow` | the repo defines a reusable workflow (`on: workflow_call`) | a workflow `uses:` it |

Keys are **normalised** so that two repositories spelling the same thing differently still
meet. `/users/:id` and `/users/{userId}` both become `GET /users/{param}`. Image tags are
stripped: `acme/api:1.2.3` and `acme/api:1.3.0` are the same image, and an org graph that only
linked exact tags would show almost no edges and the ones it showed would be an accident of who
deployed last.

Health-check endpoints (`/health`, `/readyz`, `/metrics`, …) are **excluded**. Every service has
one; publishing them would link every repository to every other and the graph would say nothing.

**Routes are published as `provides` only.** A route this repository *serves*, we can identify —
the file stands up a router. A route it *calls*, we cannot: a string that looks like a path in a
client is a guess, and a wrong edge invents a dependency that does not exist. So a missing route
edge does not mean nothing calls it, and the report says so in its diagnostics rather than
letting you assume otherwise.

## What is not here yet

**Call edges.** The graph has symbols, containment and imports — all of which resolve exactly.
It does not have "function A calls function B", because resolving that properly needs a
scope-chain walk, type binding, MRO linearisation and an arity filter, and a call edge that is
*wrong* is worse than one that is missing. A graph you cannot trust is a graph nobody uses.

**OpenSSF Scorecard per dependency.** Reported as `null` with a diagnostic.

Both are recorded in [the roadmap](https://github.com/vulnetix/cli/blob/main/docs/analyze-roadmap.md),
which also documents every metric's formula and where it came from.

## See also

- [Authentication](authentication/) — the GitHub requirement, and the three ways to satisfy it
- [Metrics](metrics/) — every metric, its formula, and its cutoffs
- [Command reference](../cli-reference/analyze/) — flags
