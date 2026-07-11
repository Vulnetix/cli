# `vulnetix analyze` — feature roadmap

This is the feature catalogue for `vulnetix analyze`. It contains no scores, no dates, and no effort
estimates. It exists to record **what the feature does, and every way the prior art has done it**, so that
when we build each piece we build it knowing what everyone else learned first.

Eleven projects were cloned and read in full for this document. Where several of them solved the same
problem, all of their approaches are recorded — the feature is enriched with each angle, never collapsed to
one. Where one of them got it wrong, that is recorded too, in [Part 9](#part-9--anti-patterns), because
avoiding their mistakes is worth as much as copying their successes.

## What `analyze` is

Two things, in one command, over one repository:

**1. A graph of the org's tech stack.** Nodes and edges inside the target repo, plus explicitly-declared
**cross-repo edges** — join keys that another repo's graph will match against. The scanner never reads a
second repository. It publishes what it provides and what it consumes, and the org-wide graph assembles
from N independent single-repo runs. This is what makes an org graph buildable from a CI job that only ever
has one checkout.

**2. Metrics for that repository, each one fully evidenced.** Business intelligence, security, quality,
maintainability, trustworthiness, activity. The rule that governs the entire format:

> **If a metric's value is 23, the report contains 23 evidence records.**
>
> A metric that hit a cap says how many items it dropped and why. A metric that could not be measured is
> null, not zero. Silent truncation is not representable.

Of the eleven projects surveyed, **not one does this.** DevStats, github-metrics-aggregator and Measure emit
aggregates with no trail back to what produced them. issue-metrics comes closest — its per-item `issues[]`
array means every statistic is traceable — and it is the only one that does. This is the differentiator, and
everything in the schema (`schemas/vulnetix-analyze-report.schema.json`) exists to enforce it.

---

## Part 0 — The reference projects

| Project | What it is | What it got right | What it got wrong |
|---|---|---|---|
| **[kospex](https://github.com/kospex/kospex)** (Python/Click, SQLite+DuckDB) | Fleet-scale git analytics: sync many repos into a DB, then query developers, tech stacks, dependencies, key-person risk across all of them. | The `_repo_id = server~owner~repo` identity grammar; one uniform development-status ladder applied to *everything* (repos, devs, dependency files, Dockerfiles); the `krunner` in-memory-DB trick for fleet queries; version-stamped rebuild guards so unchanged repos are not rescanned. | Two near-identical `sync_repo` implementations; a `/354` divisor where `/365.25` was meant; no evidence trail — the numbers are in tables, the reasons are not. |
| **[panopticas](https://github.com/kospex/panopticas)** (Python, 740 lines) | kospex's file-type and technology detector. Extension → language, shebang → language, and a 4-rule tag engine. | Tiny, dependency-free, and the tag engine is genuinely well-factored: extension rules, exact-filename rules, path-contains rules sorted most-specific-first, and pluggable function rules. Cumulative tags, so one file can be `pip`+`Python`+`dependencies`. | No git awareness, no output format of its own. Skips filtering entirely on a repo with no `.gitignore`. |
| **[GitNexus](https://github.com/abhigyanpatwari/GitNexus)** (TypeScript, embedded graph DB) | A code knowledge graph: 34 node types, 28 edge types, a 15-phase ingestion DAG, CFG/PDG/taint analysis, and a cross-repo contract bridge. | The most sophisticated prior art here by a distance. The evidence-weighted scope resolver; the cross-repo bridge (`symbolUid` as the join grain, per-repo graphs staying closed); confidence and match-type as first-class on every edge; worker-serialized parse results to survive tree-sitter's non-GC-able native buffers. | Node IDs churn when an overload is added (`save#1` becomes `save#1~int`), so they cannot be used as long-lived foreign keys. COBOL has no grammar, only regex. |
| **[gitvoyant](https://github.com/Cre4T3Tiv3/gitvoyant)** (Python, GitPython + tree-sitter) | "Temporal intelligence": walks a file's git history, computes complexity at each commit, and fits a trend to predict decay. | The idea is the valuable part — complexity as a *time series*, not a snapshot. Per-language McCabe counting via `ast`/tree-sitter. Explicit data-sufficiency gates (<5 commits → low confidence, and it says so). | The trend regresses against **commit index, not calendar time**, while reporting the slope as "per month". The CLI's colour logic and the domain layer's `is_improving` use **opposite sign conventions**. "Confidence" is a step function of commit count with no statistical basis. |
| **[git-intelligence](https://github.com/chrkaatz/git-intelligence)** (TypeScript, Express + LowDB) | A git-analytics dashboard: developer analytics, codebase health, bus factor, social-network analysis, technical debt, readiness diagnostics. | The broadest metric catalogue of any of these, with explicit thresholds for every one. Change-coupling with real O(n²) guardrails *and* a truncation-diagnostics block surfaced to the caller. Commit-hash-based cache invalidation. | Complexity is a diff-size proxy, not a real metric — and it is presented as complexity anyway. "Dependency bumps" estimated as `added/2`. Two near-duplicate LLM prompt builders, one dead. |
| **[github-metrics-aggregator](https://github.com/abcxyz/github-metrics-aggregator)** (Go, GCP/BigQuery) | Ingests GitHub webhooks into BigQuery, derives PR velocity metrics, and runs a commit-review compliance audit. | **The commit-review-status job is the single best compliance metric in this survey** — every default-branch commit joined to its PR review decision, with a temporal-containment "breakglass" exception query. Layered app-level *and* infra-level DLQs. Idiomatic Go worth copying wholesale. | At-least-once ingest with no dedup on `optimized_events`. No client-side rate limiter anywhere. A dead Beam/Dataflow-era package (`teeth`) still in the tree. |
| **[devstats](https://github.com/cncf/devstats)** (Go + ~700 SQL files) | CNCF's community-health platform. The largest metric catalogue in open source. | ~95 shared metric definitions, all as readable SQL. Affiliation as a **time-bounded SCD-2** — employer *at the time of the event*, not current employer. Bot exclusion as a maintained denylist. Emits explicit `'-'`/`Unknown` sentinel rows for zero-activity groups rather than omitting them, so "no data" never reads as "no problem". | The Go implementation lives in a *different repo* (`devstatscode`) and this one's own docs link to the dead paths. The entire dimensional model lives in a delimited string in a `series` column. |
| **[Measure](https://github.com/MeasureOSS/Measure)** (JavaScript, MongoDB) | A static-dashboard generator over pre-crawled GitHub data, focused on inside-vs-outside-the-org contribution. | **Org membership evaluated at the time of the action**, with join/leave dates — the right way to ask "was this person a maintainer when they did this". A pre-flight data-staleness check before generating anything. | Its `medianArray`/`pc95Array` helpers **index into unsorted arrays** and the "95th percentile" is not one. PR time-to-close uses `merged_at`, silently dropping every rejected PR. Two widgets are named `average*MergeTime` and compute age-since-close. |
| **[issue-metrics](https://github.com/github-community-projects/issue-metrics)** (Python, GitHub Action) | Time-to-first-response, time-to-close, time-to-answer, time-in-label over a GitHub search query. | The most rigorous statistics here (numpy mean/median/p90, properly sorted). Anchors PR response times at **ready-for-review, not creation**, so time spent in draft is not charged to the reviewer. The signed-delta label accumulator handles multi-cycle label application correctly. The only project with a real evidence trail. | Durations serialised as `"6 days, 7:08:52"` — not machine-parseable. Fails fast on rate limit with no backoff. No caching at all. |
| **[repo-health-check](https://github.com/dogweather/repo-health-check)** (CoffeeScript, browser) | A single "Effectiveness" score from the ratio of closed to open issues and PRs. | The `scaled(r) = 10r/(1+r)` mapping is a neat way to turn an unbounded ratio into a 0–10 score. Running client-side so the *user's* API quota is spent, not a server's. | The parameter is named `merged_prs` and is passed `closedPullRequestCount()`. Icon bands and description bands use different thresholds. A hardcoded 30-day window. One metric implemented out of a README promising twenty. |
| **[repolinter](https://github.com/todogroup/repolinter)** (JavaScript, archived) | A rule engine for open-source repository compliance: does it have a LICENSE, a CODE_OF_CONDUCT, a SECURITY.md, CI config, no committed binaries. | The cleanest **policy-as-data** design in the survey. Rules, fixes and axioms are all pluggable; the ruleset is JSON Schema-validated; axioms gate rules to a subset of repos (`where: ["language=javascript"]`); every result carries its targets, so the evidence is already there. Its output shape is closer to ours than anything else here. | Archived. Its own schema forbids the `contributor-count` axiom that its code implements. Documents an `=` comparator its regex does not match. |

---

## Part 1 — The graph

### 1.1 Node and edge model

**What it is.** A typed graph of everything in the repository worth pointing at: code symbols, files, packages,
services, routes, infrastructure, people. Not a call graph — a *tech-stack* graph, which is why people and
containers and CI workflows are nodes in the same graph as functions.

**Prior art.**

*GitNexus* is the deepest. 34 node tables (`File, Folder, Function, Class, Interface, Method, Struct, Enum,
Macro, Typedef, Union, Namespace, Trait, Impl, TypeAlias, Const, Static, Variable, Property, Record, Delegate,
Annotation, Constructor, Template, Module, Route, Tool, Community, Process, Section, BasicBlock, CodeElement,
CodeEmbedding`) and **one** shared relationship table discriminated by a `type` column — chosen explicitly so
that an LLM writing Cypher only has to learn one edge table. 28 edge types across six categories:

- structural: `CONTAINS`, `DEFINES`
- module: `IMPORTS`
- behavioural: `CALLS`, `ACCESSES` (with `reason: 'read'|'write'`), `FETCHES`
- type hierarchy: `EXTENDS`, `IMPLEMENTS`, `METHOD_OVERRIDES`, `METHOD_IMPLEMENTS`
- membership: `HAS_METHOD`, `HAS_PROPERTY`, `MEMBER_OF`
- process/data/DI: `STEP_IN_PROCESS`, `HANDLES_ROUTE`, `HANDLES_TOOL`, `ENTRY_POINT_OF`, `QUERIES`, `INJECTS`
- opt-in PDG: `CFG`, `REACHING_DEF`, `TAINTED`, `SANITIZES`, `TAINT_PATH`, `CDG`, `POST_DOMINATE`

Every edge carries four generic properties: `type`, `confidence` (0.0–1.0), `reason` (free-text provenance)
and `step` (ordinal).

*kospex* has a far smaller graph but a more useful one for org-level questions: developer↔repo edges
(`{nodes: [{id, node_type: 'developer'|'repo', group, status_group, commits, ...}], links: [{source, target, commits}]}`),
scoped to a repo, an org, a server, or one author. Its `status_group` (1=Active, 2=Aging, 3=Stale,
4=Unmaintained) drives node colour — the health signal is *in* the graph, not beside it.

**Evidence.** Every node and every edge is itself an evidence record (`graph_element`). A graph metric
("modules with no inbound edges: 7") references the 7 nodes.

**For us.** One graph, all kinds. `graphNode.kind` spans code symbols, infrastructure, the technology
inventory *and* people, because the questions we want to answer ("who owns the code that talks to the payment
service") cross all three. Copy GitNexus's decision to put `confidence` and `resolution` on every edge — an
edge is an inference, and a consumer must be able to filter by how sure we are.

### 1.2 Parsing and symbol extraction

**What it is.** Turning source files into typed nodes.

**Prior art.**

*GitNexus* runs tree-sitter across 16 languages behind a **unified capture-tag abstraction**: each language's
S-expression queries emit different AST node names but identical semantic capture tags (`@definition.class`,
`@definition.function`, `@definition.method`, `@call.name`, `@import.source`, `@reference.inherits`), so no
downstream code branches on language. It deliberately adds extra patterns for arrow-function-as-const, HOC-wrapped
declarations and object-property arrows, specifically so that Zustand actions and React context providers are
not invisible. It also has a `preprocessSource` hook that blanks out confusing constructs (Unreal's `UCLASS`
macros) *before* parsing, replacing elided characters with spaces so byte offsets still line up.

*gitvoyant* parses per-language for complexity only: Python via stdlib `ast`, everything else via tree-sitter,
counting decision points.

**For us.** `internal/treesitter` already wires 17 grammars and `internal/reachability/engine.go` already
gives us `Engine.Run(ctx, lang, source, query) → []QueryMatch` with pooled parsers and bounded concurrency.
The capture-tag abstraction is the piece to add: one query set per language, all emitting the same capture
names.

### 1.3 Qualified names and overload disambiguation

**What it is.** Giving a symbol a name that is unique within the repo.

**Prior art.** *GitNexus*: node ID is `Label:qualifiedName`, with disambiguation suffixes applied in order,
first hit wins — SFINAE-constraint tag, parameter-shape tag, parameter-types tag (`qn~int,string`), arity tag
(`qn#2`), template-arguments tag, plain qualified name, namespace-prefix retry, simple-name fallback. C++ adds
`$const` for const-overload collisions.

**The trap, which GitNexus documents against itself:** these are *collision-only* tags, so a node's ID
**changes when an overload is added elsewhere**. `save#1` becomes `save#1~int` the moment `save(String)` appears.
Anything persisting these IDs as foreign keys across re-indexes will silently break.

**For us.** The report schema says this out loud on `graphNode.id`. Persisted joins must key on `(repoId,
path, name)` or the PURL, not on a symbol ID whose spelling depends on code we did not change.

### 1.4 Import and call resolution

**What it is.** The hard part. Deciding which function a call site actually calls.

**Prior art.** *GitNexus* is the only project here that does this properly, and it does it with an
**evidence-scoring resolver** rather than a pile of per-language heuristics. The canonical lookup, dispatched
into identically by the class, method and field registries:

1. **Lexical scope-chain walk** — parent-ward from the call site. **Hard shadow**: if *any* binding exists at a
   scope, even of the wrong kind, stop. Outer scopes are never consulted. This is what real lexical shadowing
   does, and getting it wrong produces confidently wrong edges.
2. **Type-binding / MRO walk** — resolve the receiver's type, then walk the linearisation.
3. **Owner-scoped contributor** — members declared directly on the receiver.
4. **Kind filter.**
5. **Arity filter** — `compatible` / `unknown` / `incompatible`. If *every* candidate is incompatible, **drop
   them all** rather than emit a definitely-wrong edge. Precision over recall, chosen deliberately.
6. **Global fallback** — only when 1–3 found nothing.
7. **Rank and tie-break.**

The confidence number is not invented per call site. It composes additively from one table:

```
local: 0.55            import: 0.45          reexport: 0.4
namespace: 0.4         wildcard: 0.3         scopeChainPerDepth: -0.02
typeBindingByMroDepth: [0.5, 0.42, 0.36, 0.32, 0.3]
ownerMatch: 0.2        kindMatch: 0.0
arityMatchCompatible: 0.1   arityMatchUnknown: 0.0   arityMatchIncompatible: -0.15
globalQualified: 0.35  globalName: 0.1
dynamicImportUnresolved: 0.02
unlinkedImportMultiplier: 0.5
```

Ties break deterministically: confidence desc (within ε=0.001) → scope depth asc → MRO depth asc → origin
priority → `defId.localeCompare`. The last one exists so the same inputs always produce the same winner.

Import semantics are per-language and decide which resolution tier can even fire:

| Strategy | Languages | Behaviour |
|---|---|---|
| `named` | TS, JS, Java, C#, Rust, PHP, Kotlin | only explicitly imported names are visible |
| `wildcard-leaf` | Go, Ruby, Swift, Dart | whole-package import, no transitive re-exports |
| `wildcard-transitive` | C, C++ | `#include` closure chains through re-exports |
| `namespace` | Python | module aliases resolved at the call site |

**Unresolved calls do not vanish.** An unresolved import still produces an edge at `0.5×` weight; a dynamically
computed import gets a token `0.02`. The graph records that *something* referenced *something*, and lets the
consumer decide.

**For us.** This is the most reusable design in the survey. Adopt the evidence table wholesale, put the
resulting `confidence` and `resolution` on the edge, and never let a resolver silently drop a call it could not
resolve.

### 1.5 Communities and processes

**Prior art.** *GitNexus* runs **Leiden** over the `CALLS` subgraph to produce `Community` nodes (with
`cohesion`, `keywords`, `symbolCount`), then derives `Process` nodes (ordered `STEP_IN_PROCESS` chains from an
entry point). This is what turns a hairball into something a human can navigate.

**For us.** Directly relevant to the GUI: a repo with 5,000 nodes is unreadable, a repo with 12 communities is
not.

### 1.6 Cross-repo edges — the org graph

**What it is.** The whole reason `analyze` is a single-repo scanner that still produces an org-wide graph.

**Prior art.** *GitNexus*'s "group" system is almost exactly the problem we have, and its answer is the one to
take:

- Each repo is indexed **independently**, into its own graph, completely unaware of any group.
- A **separate, much smaller bridge store** holds `Contract` nodes and `ContractLink` edges.
- Each extracted contract carries a **`symbolUid` — literally the same node ID the per-repo pipeline assigned**.
  That is the join grain.
- Contract extraction is **graph-native, not source-native**: extractors query the *already-built* per-repo graph
  (`Route.handlerSymbolId`), so the cross-repo sync never re-parses source.
- Contract types: `http`, `grpc`, `thrift`, `topic` (message queue), `shared_libs`, `includes`, `workspace_deps`.
- Matching runs in tiers: exact (after normalisation) → manifest-declared → wildcard (`grpc::UserService/*`) →
  BM25/embedding fallback. **Every link carries its `matchType` and `confidence`** — never a boolean "linked".
- Cross-repo traversal is **clamped to one hop**, and the clamp is *surfaced* as a warning rather than silently
  truncating the answer.
- **Noise filtering matters at scale**: health-check endpoints and param-only routes are excluded, because N×M
  identical `/health` endpoints across an org flood the bridge with false positives.
- Bounded residency: never more than K repo databases open at once, with windowed batch processing.

*kospex* solves the identity half: `_repo_id = server~owner~repo`, `org_key = server~owner`, and one grammar
(`get_id_params`) that disambiguates a single string into repo / org / server / author scope.

*DevStats* solves the grouping half: repo groups where **one repo can be in many groups**, and — for Kubernetes
— groups assigned at *file-path* level, so a PR touching cluster-lifecycle files is regrouped regardless of which
repo it landed in.

**Evidence.** Every cross-repo edge carries the local node it attaches to and the evidence (the manifest line,
the route declaration) that produced its join key.

**For us.** `crossRepoEdge` in the schema is exactly this: `{localNodeId, joinKind, joinKey, role: provides|consumes,
targetRepoHint, confidence}`. The scanner publishes a key and a role; the *server* forms the edge by matching one
repo's `provides` against another's `consumes` within an org. The index that makes it work is
`(orgId, joinKind, joinKey, role)`. Join-key normalisation is the whole game: a PURL for packages,
`METHOD /normalized/path/{param}` for HTTP, `package.Service/Method` for gRPC — two repos that spell the same
route differently must still meet.

---

## Part 2 — Business intelligence

### 2.1 Technology and language inventory

**Prior art.** *panopticas* is the reference implementation, and its 4-rule cumulative tag engine is worth
copying exactly:

1. **Extension rules** — `.csproj` → `[.NET, C#, build, dependencies]`, `.jar` → `[binary]`.
2. **Exact-filename rules** (~40, case-insensitive) — `dependabot.yml` → `[Dependabot, GitHub, dependencies, security]`,
   `jenkinsfile` → `[pipeline, Jenkins]`, `claude.md` → `[Claude, AI, Claude Code]`.
3. **Path-contains rules**, checked **most-specific-first** (sorted by length descending, first match wins) —
   `.github/workflows` → `[workflow, pipeline, GitHub, Git]` is checked *before* the shorter `.github` → `[GitHub, Git]`.
4. **Function rules** — pluggable predicates, e.g. `is_pip_requirements` matching `^requirements([-._a-zA-Z0-9]*)\.(txt|in)$`.

Tags are **cumulative** — one file can carry `|pip|Python|PyPi|dependencies|`. Language detection cascades:
exact-basename map (`go.mod`, `go.sum`) → extension map → shebang (`#!/usr/bin/env python3` → last token, normalised) →
`Unknown`.

*kospex* stores those tags as a pipe-delimited string for `LIKE '%|tag|%'` querying, and cross-references
`scc`'s per-file `Language`/`Lines`/`Code`/`Comments`/`Complexity` by path.

*DevStats* derives the landscape from commit history instead (`commit_files._ext`), which answers a different
question: not "what is in this repo" but "what are people actually working in".

**Evidence.** One `file` record per file, carrying its language, its tags, and its line counts. A metric of
"47 Python files" references 47 file records.

**For us.** We already have `internal/aibom/catalog` and `internal/cbom/catalog` as the catalog-driven-detection
pattern. The technology catalog is the same shape: JSON in, `Compile()` validates every regex and glob at load,
and `just gen-analyze` regenerates the docs from it so the docs cannot drift from the detector.

### 2.2 Dependency inventory and staleness

**Prior art.** *kospex*, via deps.dev:

- **`versions_behind`** — fetch every version of the package, sort by publication date, and count the releases
  published **between the version actually pinned and the ecosystem's recommended ("default") version**. Note this
  is not "how many releases exist" — a package that pins the latest is 0 behind even if 40 releases exist.
  Version matching is fuzzy (`2022.07.13` vs `2022.7.13`, 2-part vs 3-part).
- **`advisories`** — `len(package.advisoryKeys)`. A raw count, no severity weighting.
- **"Non-compliant"** — `versions_behind > 2`. A hardcoded n-2 policy.
- **The supply-chain risk colour rule** — the clearest risk bucketing in the survey:
  ```
  Green : no advisories, no malware, 0–2 versions behind
  Yellow: no advisories, no malware, 2–6 versions behind
  Orange: has advisories, OR published > 12 months ago
  Red   : has malware,   OR published > 2 years ago
  ```
- A **"Dependency:Repo Author Ratio"** — repo authors over total dependency authors, as a rough measure of how much
  of your attack surface is written by people you do not employ.

**For us.** We already have SCA, PURLs, EOL and malware. What is missing is `versions_behind` and dependency
*age*. The `dependencyRecord` in the schema carries `declaredVersion` / `resolvedVersion` / `latestVersion` /
`versionsBehind` / `publishedAt` / `ageSeconds` / `discoveredVia`, and `discoveredVia: install-dir` with no
manifest entry is how "installed but not declared" gets said.

### 2.3 Contributor affiliation

**Prior art.** *DevStats* has the only correct model here, and it is worth stating precisely because it is easy
to get wrong:

```sql
CREATE TABLE gha_actors_affiliations (
    actor_id bigint NOT NULL,
    company_name character varying(160) NOT NULL,
    dt_from timestamp NOT NULL,
    dt_to   timestamp NOT NULL,
    ...
);
```

Every affiliation-aware query joins `aa.dt_from <= event.created_at AND aa.dt_to > event.created_at` — the
employer **at the time of the event**, not the current employer. A contributor who worked at Red Hat in 2019 and
Google in 2024 has their 2019 commits attributed to Red Hat, forever. An affiliation without a validity interval
is a bug.

It also maintains an **acquisition remap** (`companies.yaml`) so `CoreOS` folds into `Red Hat`, `Heptio` and
`Bitnami` into `VMware`, `Rancher Labs` into `SUSE`, and explicitly excludes the sentinels
`('', 'Independent', '(Robots)', 'NotFound', '(Unknown)')` from company-concentration maths so that
"unaffiliated" is never miscounted as a company.

*Measure* solves the same problem for org membership rather than employment: a contribution counts toward an org
only if the person was a member at the time the item was created, handling never-joined and never-left as explicit
cases.

**For us.** `identity.affiliation` in the schema is `{company, validFrom, validUntil, source}`. We have no
affiliation source today, so this starts empty — but the shape is right from day one, because retrofitting a
validity interval onto a `company` string means re-deriving history.

### 2.4 CI/CD and GitHub Actions inventory

**Prior art.** *kospex*'s workflow extractor parses every `uses:` in every workflow (job-level and step-level) and
classifies:

- `action_owner`, `action_name`, `pinned_version`
- **`pin_type`**: `HASH` (40-hex SHA) / `TAG` / `NONE` — the security-relevant one
- **`github_action`**: `yes` only when the owner is exactly `actions` or `github`. Microsoft and Azure are
  deliberately *not* treated as official.
- Four reference forms handled: `owner/repo[/path]@ref`, `./local-action`, `./.github/workflows/x.yml`
  (reusable workflow), `docker://image[:tag]`.

*git-intelligence* detects CI presence only (GitHub Actions dir, `.gitlab-ci.yml`, `.circleci/config.yml`,
`Jenkinsfile`) and dependency automation (`dependabot.yml`, `renovate.json`), feeding a "missing automation"
risk: `high` if neither, `medium` if one, `low` if both.

**Evidence.** One SARIF result per unpinned action reference, anchored at the workflow file and line.

---

## Part 3 — Security

### 3.1 Secrets in git history

**What it is.** Not "is there a secret in the working tree" — `secretscan` already answers that — but "was a
secret ever committed", which is the question that determines whether a credential needs rotating.

**Prior art.** *repolinter* has three distinct rules, and the distinction between them matters:

- **`git-grep-commits`** — for every commit from `git rev-list --all`, run `git grep -E "(secret|password)" <commit>`.
  Finds secrets in file *contents*, at any point in history, even if later removed.
- **`git-grep-log`** — `git log --all --format=full -E --grep=<word>`. Finds secrets in **commit messages**, which
  no content scanner will ever see.
- **`git-list-tree`** — for every commit, `git ls-tree -r --name-only`. Finds secrets in **filenames** (`secret.key`,
  `id_rsa`) even when the file's contents were never scanned.

All three run across *every reachable commit*, not just HEAD.

*kospex* shells out to gitleaks and trufflehog per repo and caches the raw JSON under
`~/kospex/krunner/<repo_id>.<TOOL>.json`, skipping the tool entirely if the cache file exists — a crude but
effective memoisation. It then aggregates counts per repo into a "secrets hotspots" heatmap.

**Evidence.** One SARIF result per finding, with the commit SHA in `properties`, the file and line in the physical
location, and the snippet — we already have `captureSnippet` and `sast.BuildSARIF`. `internal/secretscan/githistory.go`
already walks history for blobs; the message and filename passes are what is missing.

### 3.2 Commit review status — the compliance metric

**What it is.** *Which commits reached the default branch without being reviewed, and was there a justification?*
This is the best single compliance metric in the survey and nothing in our product answers it today.

**Prior art.** *github-metrics-aggregator*, in three steps.

**Step 1 — find every commit that landed on the default branch:**

```sql
WITH commits AS (
  SELECT
    JSON_VALUE(payload, '$.pusher.name') author,
    JSON_VALUE(payload, '$.repository.default_branch') branch,
    JSON_VALUE(commit_json, '$.id') commit_sha,
    TIMESTAMP(JSON_VALUE(commit_json, '$.timestamp')) commit_timestamp
  FROM events, UNNEST(JSON_EXTRACT_ARRAY(payload, '$.commits')) commit_json
  WHERE event = 'push'
    AND JSON_VALUE(payload, '$.ref') = CONCAT('refs/heads/', JSON_VALUE(payload, '$.repository.default_branch'))
)
SELECT ... FROM commits
LEFT JOIN commit_review_status USING (commit_sha)
WHERE commit_review_status.commit_sha IS NULL   -- only unprocessed; idempotent re-run
```

**Step 2 — resolve each commit's review decision** via GraphQL, keeping only PRs targeting the default branch:

```go
func getApprovalStatus(request *PullRequest) string {
    approvalStatus := GithubPRReviewRequired
    for _, review := range request.Reviews.Nodes {
        if review.State == GithubPRChangesRequested { approvalStatus = string(review.State) }
        if review.State == GithubPRApproved { return GithubPRApproved }  // any approval wins
    }
    return approvalStatus
}
```

Status is one of `APPROVED` / `REVIEW_REQUIRED` / `CHANGES_REQUESTED` / `UNKNOWN`, where **`UNKNOWN` means no
associated PR could be found at all** — deliberately distinct from `REVIEW_REQUIRED`.

**Step 3 — the breakglass exception**, and this is the elegant part. A commit that was not reviewed is not
automatically a violation; it is a violation *unless the author had an open breakglass issue at the moment they
pushed*:

```sql
SELECT JSON_VALUE(payload, '$.issue.html_url') html_url
FROM events
WHERE event = 'issues'
  AND JSON_VALUE(payload, '$.repository.name') = 'breakglass'
  AND JSON_VALUE(payload, '$.issue.user.login') = '{author}'
  AND TIMESTAMP(JSON_VALUE(payload, '$.issue.created_at')) <= TIMESTAMP('{commit_timestamp}')
  AND TIMESTAMP(JSON_VALUE(payload, '$.issue.closed_at'))  >= TIMESTAMP('{commit_timestamp}')
```

A temporal-containment query: the issue's open interval must contain the commit's timestamp. The metric is then:

```
unreviewed_unjustified = COUNT(*) WHERE approval_status != 'APPROVED' AND ARRAY_LENGTH(break_glass_issue_urls) = 0
```

Permanent errors (the repo was deleted) are written **with a `note`**, not dropped — so the evidence set stays
complete even when a commit cannot be resolved.

**Evidence.** One `commit` record per unreviewed commit, plus the `pullRequest` record if one was found, plus the
breakglass `issue` records if any. Every element of the claim is inspectable.

**For us.** This needs GitHub API access, which `analyze` may not have. When it does not, the metric is **null with
a diagnostic**, never zero. "We could not check whether commits were reviewed" and "all commits were reviewed" are
not the same sentence, and the schema will not let us conflate them.

### 3.3 Signed commits

**Prior art.** *git-intelligence* reads `%G?` from `git log` and counts a commit as signed if the status is `G`
(valid) or `U` (valid but untrusted), giving `signedCommits` and `signedCommitsPercentage` per author.

**Evidence.** `commitRecord.signature: {signed, verification}` — the schema keeps the verification state, not just a
boolean, because "signed with an untrusted key" is a different fact from "signed".

### 3.4 Committed binaries and large files

**Prior art.** *repolinter*'s `file-type-exclusion` rule fails if `**/*.exe` or `**/*.dll` exist (excluding
`node_modules`); its `large-file` rule fails any file over a byte threshold and sorts the failures largest-first.
*git-intelligence* thresholds large binaries at `{LOW: 1MB, MEDIUM: 5MB, HIGH: 10MB}` and flags anything with a
known-binary extension *or* over the medium threshold.

---

## Part 4 — Quality

### 4.1 Complexity

**Prior art.** *kospex* shells out to `scc --by-file -f csv` and stores `Lines`, `Code`, `Comments`, `Blanks`,
`Complexity`, `Bytes` per file.

*gitvoyant* computes it itself, per language, as McCabe-style decision-point counting from a base of 1:

- **Python** (stdlib `ast`): `+1` each for `If`, `While`, `For`, `AsyncFor`, `ExceptHandler`; `+len(values)-1` for
  each `BoolOp` (so `a and b and c` adds 2).
- **JS/TS** (tree-sitter): `if_statement, for_statement, for_in_statement, while_statement, do_statement,
  switch_case, catch_clause, ternary_expression`, plus each `&&`/`||`.
- **Java**: as above plus `enhanced_for_statement`, `switch_block_statement_group`.
- **Go**: `if_statement, for_statement, expression_case, communication_case, type_case`, plus `&&`/`||`.

A syntax error yields complexity 0 for that commit and analysis continues — partial data rather than an abort.

*git-intelligence* does **not** parse at all, and uses diff size as a proxy: `averageDiffSize` = mean `(added +
deleted)` per commit touching the file; `rewritePercentage` = `Σ min(added, deleted) / totalLines × 100`. It is
honest about this in its docs and dishonest about it in its UI, where the field is labelled "complexity".

**For us.** We have tree-sitter for 17 languages. Real cyclomatic complexity, per file, stored on `fileRecord.complexity`.

### 4.2 Complexity trend over history

**What it is.** The most interesting idea in the survey: complexity as a *time series* per file, so you can see a
file rotting before it has rotted.

**Prior art.** *gitvoyant*:

```
complexity_trend_slope  = polyfit(range(len(series)), complexity_series, 1)[0]
complexity_growth_rate  = (mean(last 5) − mean(first 5)) / mean(first 5)
quality_decay_forecast  = clamp(complexity_growth_rate × 2, 0.0, 1.0)
exposure_level          = HIGH if forecast > 0.7, MEDIUM if > 0.4, else LOW
confidence              = 0.9 if commits ≥ 10, 0.75 if ≥ 7, 0.6 if ≥ 5, else 0.4
                          (and capped at 0.4 entirely if fewer than 5 commits were processed)
```

It walks the file's own history (`iter_commits(paths=file, since=window, max_count=100)`), reads the blob at each
commit, computes complexity, and fits the line.

**Two things it gets wrong, both of which we must not repeat:**

1. **The regression is against commit *index*, not calendar time** — `polyfit(range(len(df)), ...)` — while the
   result is reported and documented as complexity change "per month". A file with ten commits in one day and one
   commit a year later produces a slope that means nothing.
2. **"Confidence" is a step function of commit count**, with no R², no p-value, no residual analysis. It is a
   sample-size heuristic wearing a statistician's coat.

Its docs also *describe* a volatility signal (standard deviation of complexity changes between commits) that is
**not implemented**.

**For us.** Regress against **time**, report the slope in complexity-per-day, and derive confidence from the actual
fit (R²) alongside the sample size. Evidence is the full per-commit series — `evidenceSemantics: population`, with
`populationSize` = the number of commits in the series and one `commit` record for each.

### 4.3 Change coupling

**What it is.** Files that keep changing together, which is where the hidden architectural dependencies are.

**Prior art.** *git-intelligence*: for every commit, increment a counter for every pairwise `(file1, file2)` within
that commit. Then:

```
coChangePercentage = coChanges / min(file1Commits, file2Commits) × 100
```

kept only for pairs with `coChanges ≥ 3`. The `min()` denominator is the right choice — it asks "of the times the
*rarer* file changed, how often did the other change too", which does not penalise a pair just because one file is
touched constantly.

The naive implementation is O(files²) per commit and explodes on a merge commit touching 900 files, so it has hard
guardrails: `COUPLING_MAX_COMMITS = 20000`, `COUPLING_MAX_FILES_PER_COMMIT = 120`, `COUPLING_MAX_PAIR_KEYS = 100000`,
`COUPLING_MAX_RESULTS = 1000` — **and it surfaces a `ChangeCouplingDiagnostics` block** reporting
`commitsProcessed`, `commitsSkippedByLimit`, `largeCommitCountCapped`, `pairLimitHit`, `isTruncated`. It is the only
project in the survey that tells you when it gave up.

**For us.** This is exactly what `evidenceCompleteness: truncated` + `omittedCount` + `truncationReason` is for. Adopt
the guardrails and the honesty.

### 4.4 Hotspots and stability

**Prior art.** *kospex*: `repo_hotspots` (commits, authors, files, LOC, first/last seen). *git-intelligence*: file
and directory commit-count rankings, with lockfiles and translation files excluded from the ranking (they churn for
uninteresting reasons). Stability buckets:

```
unstable  if ageDays < 90  AND changeFrequency > 10
stable    if ageDays > 365 AND changeFrequency < 5
evolving  otherwise
```

### 4.5 Technical-debt detectors

**Prior art.** *git-intelligence* runs ten in parallel, each with explicit thresholds:

| Detector | Rule |
|---|---|
| Commented-out code | regex over unified diffs of the last 100 commits (50 analysed for diff detail); `high ≥ 20` lines, `medium ≥ 10`, `low ≥ 5` |
| Huge commits | `{LOW: 500, MEDIUM: 1000, HIGH: 2000}` lines; `riskScore = added + floor(removed × 0.1)` — deletions weighted at 10%, because a cleanup is not a risk |
| WIP commits | message contains `wip, work in progress, draft, todo, fixme, xxx, hack, temp, temporary` |
| Quick-fix commits | `quick fix, quickfix, temporary fix, bandaid, band-aid, hotfix, workaround` |
| Large binaries | `{LOW: 1MB, MEDIUM: 5MB, HIGH: 10MB}` |
| Vendored-code growth | dirs matching `vendor, third_party, libs, external, dependencies`; file count at first commit vs HEAD; `{LOW: 50%, MEDIUM: 100%, HIGH: 200%}` growth |
| Long-lived branches | `{LOW: 30, MEDIUM: 90, HIGH: 180}` days since creation (creation = first commit after `merge-base` with default) |
| Branch proliferation | `{LOW: 10, MEDIUM: 20, HIGH: 50}` non-default branches; `activeBranches` = commits in last 90d |
| Dependency drift | lockfile not updated in `{LOW: 90, MEDIUM: 180, HIGH: 365}` days |
| Missing automation | `high` if neither CI nor dependency bot; `medium` if one; `low` if both |

The commented-out-code detector only looks at the last 100 commits, so debt introduced earlier is invisible — a real
limitation, and one that should be a *diagnostic* in our output rather than a footnote in a README.

---

## Part 5 — Maintainability

### 5.1 The development-status ladder

**Prior art.** *kospex*, and its virtue is that it is **one ladder applied to everything**:

```
days ≤ 90            → Active
90  < days ≤ 180     → Aging
180 < days ≤ 365     → Stale
days > 365           → Unmaintained
None                 → Unknown
```

Applied uniformly to repos (last commit), developers (last commit), dependency files (last commit to that file), and
Dockerfiles. The consistency is the feature: a reader learns the ladder once.

kospex also has a second, finer ladder for tenure and age buckets: `Single day` (1), `< 3 months` (90), `< 6 months`
(180), `< 1 year` (365), `< 2 years` (730), `2+ Years`.

**For us.** `metric.classification` carries both the `label` and the `thresholds` string that produced it, so the
ladder travels with the verdict and a consumer can check our arithmetic.

### 5.2 Orphaned repositories

**Prior art.** *kospex*: a repo is orphaned when **none of the people who committed to it in the last year are still
active anywhere in the org**. Concretely: `active_set` = every author with a commit in the last 90 days across *all*
repos; `committers` = distinct committers to this repo in the last 365 days; orphaned iff
`|committers ∩ active_set| == 0`. Otherwise it reports `% Here` — the fraction of the repo's recent committers who are
still around.

This is a genuinely good metric and it is *inherently cross-repo* — it cannot be computed from one repo alone. Our
scanner emits its half (this repo's recent committers, as evidence records); the org-level rollup computes the
intersection.

### 5.3 Health trend

**Prior art.** *DevStats*'s `projects_health.sql` — a ~2,200-line SQL file that, per repo group, computes committers,
contributors, commits, PRs opened/closed/merged for the **trailing 3 / 6 / 12 months** *and* the **preceding 3-month
window**, and emits an Up/Down/Flat indicator:

```sql
case comm3 > commp3 when true then 'Up'
     else case comm3 < commp3 when true then 'Down' else 'Flat' end end
```

Plus days-since-last-commit, an Active/Inactive flag at 90 days, issue-responsiveness percentiles, and top-company
concentration.

**Crucially**: repo groups with zero activity emit explicit `'-'` / `'Unknown'` / sentinel-date rows rather than being
absent from the result. **"No data" must never render as "no problem"** — a green dashboard because a collector failed
is worse than a red one.

---

## Part 6 — Trustworthiness

### 6.1 The policy rule engine

**Prior art.** *repolinter*, and its architecture is the closest thing in the survey to what our report already is.

A **ruleset** is JSON/YAML, JSON Schema-validated, and can `extend` another ruleset by URL or path (deep-merged,
capped at 20 levels):

```json
{
  "version": 2,
  "axioms": { "linguist": "language", "licensee": "license", "packagers": "packager" },
  "rules": {
    "license-file-exists": {
      "level": "error",
      "rule": { "type": "file-existence", "options": { "globsAny": ["LICENSE*", "COPYING*"], "nocase": true } },
      "policyInfo": "...", "policyUrl": "..."
    },
    "javascript-package-metadata-exists": {
      "level": "error",
      "where": ["language=javascript"],
      "rule": { "type": "file-existence", "options": { "globsAny": ["package.json"] } }
    }
  }
}
```

`level` is `error` / `warning` / `off`. Only an `error`-level failure fails the run; a `warning` never changes the exit
code; `off` is skipped entirely and reported as `IGNORED` rather than silently vanishing.

**The 18 rule types**: `file-existence`, `file-not-exists`, `directory-existence`, `file-contents`,
`file-not-contents`, `file-hash`, `file-hashes-not-exist`, `file-starts-with`, `file-type-exclusion`,
`file-no-broken-links`, `git-working-tree`, `git-grep-commits`, `git-grep-log`, `git-list-tree`, `large-file`,
`license-detectable-by-licensee`, `json-schema-passes`, `apache-notice`, `best-practices-badge-present`.

**The 3 fix types**: `file-create`, `file-modify` (prepend/append, with newline padding control), `file-remove`. Fixes
run only when the rule failed, and target the *failing* paths automatically. `--dryRun` reports what it would do.

**The axiom system** is the part worth stealing. An axiom classifies the repo, and its results become gate labels:

| Axiom | Produces |
|---|---|
| `licensee` | SPDX license IDs detected |
| `linguist` | languages detected |
| `packagers` | package managers, by manifest presence: `pom.xml`→maven, `package.json`→npm, `setup.py`→pypi, `*.nuspec`→nuget, `*.podspec`→cocoapod, `Cargo.toml`→cargo, `*.gemspec`→rubygem, `DESCRIPTION`→cran, `Makefile.PL`/`Build.PL`→cpan, `ivy.xml`→ivy, `build.gradle`→gradle |
| `contributor-count` | a **numeric** axiom — supports `where: ["contributors>6"]` via the comparator regex `([\w-]+)((?:>|<)=?)(\d+)` |

A rule runs only if **every** `where` clause is satisfied; an unsatisfied clause produces an explicit `IGNORED`
result with the message `ignored due to unsatisfied condition(s): "..."`. Nothing is ever silently skipped.

**Its result model** is already evidence-shaped:

```js
Result   { message, targets: ResultTarget[], passed }
ResultTarget { path?, pattern?, passed, message? }   // pattern when nothing matched, so a miss is still a record
FormatResult { ruleInfo, runMessage, status, lintResult, fixResult }
status ∈ PASSED | NOT_PASSED_ERROR | NOT_PASSED_WARN | IGNORED | ERROR
```

Note `ResultTarget.pattern`: when a glob matched nothing, the evidence records **the glob that was searched**, so the
absence is itself evidenced. That is exactly the discipline our schema demands.

### 6.2 The OSS compliance checklist

**Prior art.** *repolinter*'s shipped default ruleset — the exact file lists, which are worth transcribing rather
than reinventing:

| Rule | Patterns |
|---|---|
| `license-file-exists` | `LICENSE*`, `COPYING*` (nocase) |
| `readme-file-exists` | `README*` (nocase) |
| `contributing-file-exists` | `{docs/,.github/,}CONTRIB*` |
| `code-of-conduct-file-exists` | `{docs/,.github/,}CODEOFCONDUCT*`, `CODE-OF-CONDUCT*`, `CODE_OF_CONDUCT*` |
| `changelog-file-exists` | `CHANGELOG*` |
| `security-file-exists` | `{docs/,.github/,}SECURITY.md` (case-**sensitive**) |
| `support-file-exists` | `{docs/,.github/,}SUPPORT*` |
| `readme-references-license` | README must match `/license/i` |
| `code-of-conduct-file-contains-email` | CoC must match `.+@.+\..+` |
| `binaries-not-present` | fails on `**/*.exe`, `**/*.dll` (excluding `node_modules/**`) |
| `test-directory-exists` | `**/test*`, `**/specs` |
| `integrates-with-ci` | `.gitlab-ci.yml`, `.travis.yml`, `appveyor.yml`, `circle.yml`, `.circleci/config.yml`, `Jenkinsfile`, `.drone.yml`, `.github/workflows/*`, `azure-pipelines.yml` |
| `source-license-headers-exist` | *warning* — first 5 lines of `**/*.js` must contain `Copyright` and `License` |
| `github-issue-template-exists` | `ISSUE_TEMPLATE*`, `.github/ISSUE_TEMPLATE*` |
| `github-pull-request-template-exists` | `PULL_REQUEST_TEMPLATE*`, `.github/PULL_REQUEST_TEMPLATE*`, `docs/pull_request_template.md` |
| `notice-file-exists` | `NOTICE*` — only `where: ["license=Apache-2.0"]`, citing Apache §4.4 |
| per-language package metadata | `where: ["language=X"]` → `package.json` (js), `Gemfile` (ruby), `pom.xml`/`build.xml`/`build.gradle` (java), `setup.py`/`requirements.txt` (python), `Cartfile`/`Podfile`/`*.podspec` (objc), `Package.swift` (swift), `rebar.config` (erlang), `mix.exs` (elixir) |
| `best-practices-badge-present` | README matches `https://bestpractices.coreinfrastructure.org(/\w+)?/projects/\d+`; with `minPercentage`, fetches the badge API and checks `tiered_percentage` (passing=100, silver=200, gold=300) |

### 6.3 OpenSSF Scorecard

**For us.** Scorecard answers the repo-practice questions (branch protection, code review, signed releases, pinned
dependencies, dangerous workflows, token permissions) with an established, recognised vocabulary. The schema embeds
its result document as an attachment and lets a metric reference an individual check or one of its `details` lines.

Note the trap the schema guards: a Scorecard check score of **-1 is Inconclusive, not 0**. A check that could not run
must never be averaged in as a failure.

---

## Part 7 — Activity

### 7.1 Bus factor and key-person risk

**What it is.** How few people would have to leave before the project is in trouble. Four projects answer it four
different ways, and all four are worth having.

**Angle 1 — *DevStats*: the classic definition.** Rank contributors by activity descending, take the cumulative
percentage, and find **the smallest number of people whose combined share first exceeds 50%**:

```sql
select repo_group, metric, tp,
  min(row_number)         as bus_factor,
  min(cumulative_percent) as percent,
  max(row_number) - min(row_number) as others_count,
  100.0 - min(cumulative_percent)   as others_percent
from cumulative_ranked
where cumulative_percent > 50.0
group by repo_group, metric, tp
```

Computed independently across nine activity types (commits, contributions, pushes, reviews, issues, PRs, merged PRs,
comments, active repos) and for both individuals **and companies** — "how many *companies* account for >50% of the
work" is often the scarier number.

**Angle 2 — *git-intelligence*: per-file ownership.** A file is a single-maintainer risk when it has ≥3 commits and
`maxAuthorCommits / totalCommits ≥ 0.70`. Level: `high` at ≥90%, `medium` at ≥80%, `low` otherwise. The same rule
applied repo-wide gives a repo risk level. It also computes:

- **Fragmentation** — files with ≥10 commits and ≥5 distinct authors (`high` at ≥10 authors) — the opposite failure
  mode, where nobody owns anything.
- **Owner churn** — sort a file's authors by last-commit date, compare the top two; flag when the ownership transition
  happened within the last 180 days *and* the previous owner held ≥30%. This catches the dangerous window right after
  a handover.

**Angle 3 — *kospex*: the key-person table.** Per repo, take the top-N by all-time commits, then **union in the top-N
by 90-day-active commits** so both the historical experts and the current maintainers appear even when those are
disjoint sets. Report `% commits`, `% active`, and tenure per person. No single risk number — a table, and the reader
draws the conclusion. (Note kospex's tenure divides by 354, which is a typo for 365.)

**Angle 4 — *Measure*: membership-aware.** Whether a contribution counts toward the org depends on whether the person
was a member *at the time*, using join/leave dates.

**Evidence.** The bus factor is `evidenceSemantics: population` — the value is a count of people, but the evidence is
the **whole ranked contributor list** the cumulative share was computed from, because the number is meaningless without
the distribution behind it.

### 7.2 Contributor lifecycle

**Prior art.** Every project has a slightly different vocabulary; all of them are useful.

- ***DevStats* — new vs episodic.** A *new* contributor has no PRs before the window. An **episodic** contributor is
  new in the window *and* had **≤12 lifetime PRs before it** — the drive-by contributor, distinguished from the
  regular. A 3-month lookback separates "recently new" from "brand new".
- ***Measure* — joining and leaving.** *Leaving*: active in months (−3, −1) but absent in (−1, now). *New*: active in
  the last month, never before.
- ***git-intelligence* — dormancy.** `active` if last commit < 90 days; `dormant` if < 365; `inactive` otherwise.
- ***kospex* — leavers with tenure.** A leaver is inactive > 90 days but *was* active within the last 365 (people gone
  over a year are excluded as noise). Bucketed by `years_active` into `<1, 1-2, 2-3, 3-4, 4-5, 5+`, which answers
  "are we losing juniors or seniors".
- ***kospex* — onboarding ramp.** `days_to_Nth_commit` (default N=11): elapsed time from a developer's first commit to
  their 11th. A proxy for how long it takes a new hire to become productive. Reports `N/A (< 11 commits)` rather than
  a misleading number.

**Evidence.** One `contributor` record per person, carrying `firstSeenAt`, `lastSeenAt`, `commits`, `commitsInWindow`,
`tenureSeconds`, `status`.

### 7.3 Issue and pull-request timing

**Prior art.** *issue-metrics* has the most careful definitions here, and the care is in the edge cases.

| Metric | Definition | The subtlety |
|---|---|---|
| **Time to first response** | `min(first_comment, first_review) − issue_time` | `issue_time` is `ready_for_review_at ?? created_at` for PRs — **draft time is not charged to the reviewer**. Excludes bots, ignored users, **the author's own comments**, and any comment before ready-for-review. |
| **Time to first review** | first *submitted review*, not comment | A comment is not a review. |
| **Time to close** | `closed_at − created_at` | For PRs, routed through **time-to-merge** instead: `merged_at − (ready_for_review_at ?? created_at)`, and **null if never merged** — a rejected PR has no merge time, and inventing one is a lie. |
| **Time to answer** | `answerChosenAt − createdAt` (discussions) | |
| **Time in draft** | Σ over every draft↔ready cycle | Handles **multiple** draft toggles, not just the first. If the PR is *still* open and in draft, adds `now − draft_start` — the one place the tool explicitly counts an open-ended interval, and it says so. |
| **Time in label** | Σ over every apply/remove cycle | A running-total-via-signed-delta trick: subtract on `labeled`, add back on `unlabeled`. Label events **after `closed_at` are skipped**. Still-open-and-labelled uses the live clock. |

Statistics: `numpy` mean, median and **90th** percentile — properly computed, unlike Measure.

*DevStats* uses `percentile_disc` for p15 / median / p85 and adds two refinements worth taking:

- **First non-author activity** filtered to `updated_at > created_at + 30 seconds`, to exclude bot auto-actions that
  fire instantly and would otherwise make every response time look like zero.
- **Time to assign** explicitly excludes **self-assignment** (`actor_id != user_id`).
- **PR age** counts open PRs and merged PRs but **excludes PRs closed without merging** — a deliberate rejected-PR
  filter, and one it documents.

*Measure* computes the same shapes and gets two of them wrong (see [Part 9](#part-9--anti-patterns)).

*github-metrics-aggregator* derives PR velocity from a denormalised table where `reviews` is the aggregated distinct
reviewer list **excluding the PR author** — so a self-approval never counts as review coverage.

**Evidence.** One `pullRequest` / `issue` record per item, with every timestamp *and* the computed
`durations` in **integer seconds**. The aggregate is `evidenceSemantics: population` over the whole item set.

### 7.4 Firefighting and reverts

**Prior art.** *git-intelligence*: `fixCommits` matching `/^(fix|bug|hotfix|patch|repair|resolve|correct)/i` and
`revertCommits` matching `/^(revert|undo|rollback)/i`, as ratios per author. Its readiness-diagnostics module also
computes **high-risk overlap**: the intersection of the top-20 churn files and the top-20 bug-fix-touched files —
"prioritise intersections over single signals, because high churn alone can just be normal activity".

*git-intelligence* is also the only project that ships **caveats with its output**: static disclaimers that
squash-merge workflows make contributor counts reflect the merger rather than the author, and that bug-touch signals
depend entirely on how consistently commit messages are written. Our schema has `diagnostic.caveat` for precisely this
— a limitation belongs in the report, not in a README nobody reads.

### 7.5 Churn

**Prior art.** *git-intelligence*: a file's "creator" is its first author; if a **different** author modifies it within
`CHURN_WINDOW_DAYS = 30` of its first commit, those lines count as churn. `churnRatio = churnLines / totalLines × 100`.
This measures rework, not activity.

---

## Part 8 — Cross-cutting concerns

### 8.1 Identity normalisation

**What it is.** The same human, spelled four ways, must not be four contributors.

**Prior art.**

- ***kospex***: an `email_map` table (`alias_email → main_email`) plus a `commits_view` that resolves
  `COALESCE(m.main_email, c.author_email) AS canonical_email`. Manual, explicit, auditable.
- ***git-intelligence***: two passes — merge by normalised email, then merge by **name similarity ≥ 0.85** using
  Levenshtein (exact = 1.0, normalised-alphanumeric match = 0.95, substring containment = length ratio, else
  `1 − distance/len`). Automatic, and therefore capable of being wrong.
- ***DevStats***: a commit has **three** identities — the pusher (`dup_actor_login`), the git author, and the git
  committer — and virtually every commit metric **unions all three** to avoid undercounting. It also parses
  `Co-authored-by:` trailers as a first-class contribution signal.
- ***kospex***, on GitHub noreply addresses: `12345+handle@users.noreply.github.com` → split on `+`, take the handle.

**For us.** `contributorRecord.aliases[]` records **every identity merged in and the rule that merged it**
(`exact-email` / `mailmap` / `normalized-email` / `name-similarity` / `github-handle` / `manual`) with a confidence.
Identity merging is a judgement, and a judgement in a report must be auditable.

### 8.2 Bot exclusion

**Prior art.**

*DevStats* maintains a denylist of ~90 exact bot logins plus ~15 globs (`%-bot`, `bot-%`, `%[bot]%`, `%-ci`, `k8s-%`,
`codecov-%`, `%clabot%`, …), injected into every actor-attributed query as a `{{exclude_bots}}` fragment. **It now
includes `copilot`, `claude` and `codex`** — AI coding agents are counted as bots for contribution purposes. There is
a companion `only_bots.sql` to invert the filter.

*kospex*'s `EmailAnalyzer` is a 4-tier cascade: exact match against 5 GitHub system addresses → substring match against
17 named CI/dependency bots (dependabot, renovate, greenkeeper, snyk-bot, whitesource-bolt, pyup-bot, jenkins, travis,
circleci, gitlab-ci, azure-devops, codecov, sonarcloud, codacy, deepsource) → 12 generic keywords (automation, deploy,
build, service, system, robot, script, pipeline, security, vulnerability, docs, wiki) → **numeric-only username** after
stripping the GitHub `+`-prefix and `[bot]` suffix.

It also classifies the email domain: `noreply` → github → personal (11 known providers) → `.edu` academic → `.gov`
government → `.org` organization → corporate.

**For us.** `identity.isBot`, `identity.botKind` and `identity.botRule` — and `botKind` has an **`ai-agent`** value
distinct from `ci` and `dependency-bot`, because a commit authored by a coding agent is neither a human contributor nor
a Jenkins job, and collapsing it into either distorts contributor counts and bus factor. We already detect AI agents in
`internal/aibom/detect_commits.go`; that detector is the source for this classification.

### 8.3 Caching and incrementality

**Prior art.**

- ***git-intelligence***: **commit-hash-based invalidation** — `git log --all -1 --format=%H` compared against the
  cached hash; a mismatch drops the cache entirely. Falls back to a 30-day TTL only when the hash cannot be read. This
  is the simplest correct answer and it is the one to copy.
- ***kospex***: a **version-stamped rebuild guard** — a file-metadata rebuild is triggered only if HEAD changed *or*
  the detector's version string changed *or* `--force`. Upgrading the tool invalidates the cache automatically, which
  prevents replaying pre-upgrade results against a new schema.
- ***GitNexus***: a **content-addressed parse cache** keyed on `sha256(filePath:contentHash for each file in the chunk)`,
  with the tool version baked into the cache key so an upgrade invalidates it. Claims a 98% speedup when 1 of 50 chunks
  is invalidated.
- ***Measure***: SHA-1 hashes its own source directory and config; if either changed, it forces a full regeneration
  regardless of data staleness.
- ***DevStats***: a `gha_computed` table memoising (metric, period) pairs so an hourly sync only recomputes the newest
  incomplete period.

**For us.** Cache key = HEAD SHA + catalog version + CLI version. All three, because a stale cache that survives a
detector upgrade is a silent correctness bug.

### 8.4 Scale guardrails, and the rule against silent truncation

**Prior art.**

- ***GitNexus***: max file size 512 KB (configurable, hard-clamped to tree-sitter's buffer ceiling); worker pool sized
  `availableParallelism() − 1` clamped to [1, 16] — and it uses `availableParallelism()` specifically so **cgroup CPU
  quotas are honoured** rather than over-sizing the pool in a container; ~20 MB byte-budget chunks; embeddings skipped
  entirely above 50,000 nodes. Skipped-file counts *and* a preview of the skipped paths are surfaced to the operator.
- ***git-intelligence***: the coupling guardrails, with the diagnostics block.
- ***DevStats***: zero-activity groups emit explicit sentinel rows.

**The rule for us, and it is not negotiable:** a cap that was hit is reported. `evidenceCompleteness: truncated` with
`omittedCount` and `truncationReason` is the only way to express a partial result, and a report that quietly carries
fewer evidence items than its metric claims is rejected by the validator — the CLI's and the server's both. This is the
one guarantee the whole format exists to make.

---

## Part 9 — Anti-patterns

Each of these was observed in a reference project. Each is a way to be confidently wrong, which is worse than being
uncertain.

1. **Metrics with no evidence trail.** DevStats, github-metrics-aggregator and Measure all emit aggregates you cannot
   drill into. When a number is surprising, the only recourse is to re-derive it by hand. *Our answer: every metric
   references every item behind it.*

2. **Percentile helpers that index unsorted arrays.** Measure's `medianArray(a)` is `a[floor(len/2)]` and its
   `pc95Array(a)` is `a[floor(0.95 × (len−1))]` — with a code comment admitting it is "not strictly the 95th
   percentile". Several callers pass unsorted input. The result is a number that looks like a statistic and is not one.

3. **A trend regressed against the wrong axis.** gitvoyant fits complexity against **commit index** and reports the
   slope as "per month". Ten commits in a day and one a year later produce a number that means nothing. *Regress against
   time.*

4. **"Closed" silently standing in for "merged".** repo-health-check's `effectiveness(merged_prs, ...)` is passed
   `closedPullRequestCount()`. Measure's PR time-to-close uses `merged_at`, so every rejected PR vanishes from the
   metric entirely rather than being counted as a rejection. *A rejected PR is data, not an inconvenience.*

5. **Durations as unparseable strings.** issue-metrics emits `"6 days, 7:08:52"` in its JSON. *Integer seconds, always.*

6. **Different thresholds for the label and the icon.** repo-health-check's icon bands are 0/3/4.5/7/10 and its
   description bands are 0/4/7/10, so a score of 3.5 shows a neutral face and the words "In the weeds".

7. **No rate-limit backoff.** issue-metrics catches `RateLimitExceededException` and calls `sys.exit(1)`.

8. **At-least-once ingest with no dedup.** github-metrics-aggregator's `optimized_events` is fed by a native Pub/Sub→BigQuery
   subscription with no idempotency, so duplicate `delivery_id` rows are possible and every downstream consumer must
   remember to `SELECT DISTINCT`. Most will not.

9. **Silent truncation.** Almost universal. git-intelligence is the honourable exception, and it is the only one that
   tells you when it gave up.

10. **Zero and unmeasured conflated.** A collector that failed and a repo with nothing to find produce the same green
    dashboard. *Null is not zero, and the schema will not let us pretend otherwise.*

11. **Dead code shipped as features.** github-metrics-aggregator's `teeth` package references tables that no longer
    exist. GitNexus declares a `WRAPS` edge type with no emitter. gitvoyant declares `developer_count` and
    `change_frequency` on its core entity and never populates either. A schema field that is never written is a promise
    that will be believed.

---

## Part 10 — Surfaces

**Report.** `.vulnetix/analyze.report.json`, validated against `schemas/vulnetix-analyze-report.schema.json` before it
is written or uploaded. Attachments — SARIF, OpenVEX, CycloneDX, SPDX, Scorecard — are each complete, standalone
documents of their own format, so `attachments.sarif` can be lifted out and fed to any SARIF tool untouched.

**Terminal.** `-o pretty` (summary tables per family, via `internal/display`), `-o json` (the full report).

**Upload.** `POST /v2/cli.insights`, best-effort and never fatal — an upload failure leaves the local report
authoritative, exactly as `aibom`, `cbom` and `malscan` behave. (`/v2/cli.analyze` was already taken by ELF binary
analysis.)

**CI gate.** `--fail-on` opting into a non-zero exit on a chosen breach, following `cbom`'s precedent — default is exit
0, because a tool that fails a build by default gets removed from the build.

**GUI.** The org graph at `/vdb-graph`, assembled server-side by matching one repo's `provides` join keys against
another's `consumes`, within the org.

**Catalog.** Metric definitions, technology detection rules and policy rules all live in
`internal/analyze/catalog/*.json`, compiled and validated at load (`Compile()`), overridable with `--catalog`, and the
source of truth for the generated docs (`just gen-analyze`). A metric's definition string in the report comes from the
catalog — so what the docs say, what the validator enforces, and what the report claims are the same sentence.
