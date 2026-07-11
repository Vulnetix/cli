---
title: "Metrics"
weight: 2
description: "Every metric analyze reports, its formula, its cutoffs, and what its evidence is."
---

Every metric carries its own definition in the report — formula and cutoffs, verbatim — so you
never have to come here to find out what a number means. This page is the same information,
gathered.

Every metric also carries its **evidence**: the things that produced it. A count of 23 has 23
evidence records; a median has the whole population it was computed over. Click a number in the
console and it opens into the list.

---

## Activity

| Metric | Definition |
|---|---|
| `activity.commits.total` | Commits reachable from HEAD in the window. |
| `activity.commits.human` | Commits whose author is not a bot or an AI agent. |
| `activity.commits.bot` | Commits by CI, dependency or service bots. |
| `activity.commits.ai_agent` | Commits by an AI coding agent — counted **separately** from both humans and CI bots, because an agent's commit is neither, and folding it into either distorts contributor counts in a different direction. |
| `activity.contributors.total` | Distinct human contributors after identity merging. Co-authors count. |
| `activity.contributors.active` | Committed within the last 90 days. |
| `activity.contributors.new` | First commit within the last 90 days. |
| `activity.contributors.departed` | Silent for more than 90 days but active within the last 365. Somebody gone two years is history, not churn. |
| `activity.bus_factor.commits` | **The smallest number of contributors whose cumulative share of commits, ranked descending, first exceeds 50%.** Bots excluded. The evidence is the *whole ranked list* — a bus factor of 2 means nothing without the distribution behind it. |
| `activity.ownership.top_contributor_share` | The single most prolific contributor's share of all human commits. |

### From the forge

| Metric | Definition |
|---|---|
| `activity.pull_requests.merged` / `.rejected` / `.open` | A pull request closed **without merging is a rejection**, counted separately. It is not a merge and it has no merge time. |
| `activity.time_to_first_response.{median,p90,mean}` | Seconds from a pull request becoming **ready for review** — not from when it was opened — to the first comment or review by somebody other than the author, excluding bots. Draft time is not charged to the reviewer. |
| `activity.time_to_first_review.*` | To the first *submitted review*. A comment is not a review. |
| `activity.time_to_merge.*` | Ready-for-review → merge. Computed **only** for pull requests that were merged. |
| `activity.issues.unanswered` | Issues with no comment from anybody but the author. **Excluded from the response-time statistics** — an issue nobody answered has no response time, and averaging it in as a zero would say the opposite of the truth. |

---

## Security

| Metric | Definition |
|---|---|
| `security.commits.unreviewed` | **Commits on the default branch whose pull request has no approving review from anybody other than the author.** Merge commits excluded. The best compliance metric there is: a repository can have perfect review coverage on its pull requests and still have half its commits pushed straight to `main`. |
| `security.commits.review_unknown` | Commits with **no resolvable pull request at all**. Deliberately *not* counted as unreviewed — we could not tell, and "we could not tell" is a different claim from "nobody reviewed it". Collapsing them turns an absence of evidence into an accusation. |
| `security.pull_requests.unreviewed` | Merged with no approving review from anybody else. |
| `security.pull_requests.self_merged` | The author merged their own work with nobody else approving. |
| `security.secrets.commit_messages` | **A credential written into a commit message.** No content scanner looks here, because the message is not a file. It is in the object database permanently. |
| `security.secrets.committed_files` | Files whose names mark them as credentials (`id_rsa`, `.env`, `*.pem`, service-account JSON, keystores) that appear **anywhere in history**, whether or not they still exist at HEAD. Deleting a file does not unpublish it. |
| `security.commits.signed` | Commits carrying a PGP signature. **Presence only** — verifying it needs the signer's public key, which the CLI does not have, so a signed commit is reported as present-but-unverified rather than valid. |

The secrets metrics answer a different question from a normal secret scan. Not "is there a
secret in the code" but **"does a credential need rotating"** — and a secret removed in the next
commit is still a secret that was published.

---

## Quality

| Metric | Definition |
|---|---|
| `quality.complexity.median` / `.p90` | Cyclomatic complexity — decision points plus one — per language, via tree-sitter. Files in languages with no grammar are **excluded, not scored zero**. |
| `quality.complexity.high` | Files at or above the threshold (default 15). |
| `quality.complexity.rising` | **Files whose complexity is trending upward:** a least-squares slope of more than 0.01 per **day**, with **R² ≥ 0.5** so the line actually fits. Regressed against calendar time, not against the commit index — a file with ten commits in one afternoon and one a year later has a per-commit slope that means nothing. |
| `quality.coupling.pairs` | Files that change together in ≥ 3 commits. Strength is `coChanges / min(commits to either file) × 100` — the *minimum*, so a pair is not judged by how often the busier of the two is touched. |
| `quality.coupling.strong` | Pairs that change together ≥ 70% of the time. **The hidden architectural dependencies**: two files that must move together, with nothing in the code to say so. |
| `quality.hotspots` | Both frequently changed (≥ 5 commits) **and** complex. Churn alone is normal activity; churn crossed with complexity is where the cost is. |
| `quality.commits.fix` / `.revert` | Corrective and firefighting commits, by message prefix. |

Commits touching more than 60 files are **excluded** from coupling: a bulk rename couples
nothing, and including it would make every file appear coupled to every other. The count says so.

---

## Maintainability

| Metric | Definition |
|---|---|
| `maintainability.repo.status` | `Active` ≤ 90d, `Aging` ≤ 180d, `Stale` ≤ 365d, else `Unmaintained` — from the most recent commit. **One ladder, applied to everything**, so you learn it once. |
| `maintainability.ownership.single_maintainer` | Files with ≥ 3 commits where one author holds ≥ 70%. The knowledge-concentration risk. |
| `maintainability.ownership.fragmented` | Files with ≥ 10 commits touched by ≥ 5 authors. The opposite failure: nobody owns it. |

---

## Trustworthiness

`trust.policy.breaches` — compliance checks with no satisfying file. Each breach records **the
globs that were searched**, because "no license" is an accusation and "we looked for `LICENSE*`,
`LICENCE*`, `COPYING*` and found none" is a finding.

Checked: license, README, contributing guide, code of conduct, security policy, changelog,
support policy, code owners, issue and pull-request templates, CI configuration, dependency
automation, tests.

---

## Business

| Metric | Definition |
|---|---|
| `business.dependencies.stale` | More than **2 releases behind** the version the ecosystem recommends. `versionsBehind` counts releases published *between the resolved version and the recommended one* — **not** the total number of releases, so a package pinned to the newest version is zero behind however long its history is. |
| `business.dependencies.very_stale` | More than 6 behind. At this distance an upgrade is a project, not a bump. |
| `business.dependencies.eol` | Past end-of-life. No further security fixes, regardless of what is found. |
| `business.dependencies.aged` | Resolved version published over a year ago. Not automatically a problem — some libraries are finished — but combined with an advisory it means nobody is coming to fix it. |
| `business.language.*` | Source files per language. |

Staleness needs registry metadata, which needs Vulnetix authentication. Without it these are
`null` with a reason — **not zero**. "Nothing is stale" is a claim an unauthenticated run has
not earned.

---

## Graph

| Metric | Definition |
|---|---|
| `graph.symbols.total` | Functions, methods, classes and interfaces. |
| `graph.imports.resolved` | Imports that resolve to a file **in this repository**. An import that resolves to nothing produces no edge at all, rather than a guess with a confidence attached to it. |
| `graph.cross_repo.total` | Every join key published for the org graph. |
| `graph.cross_repo.{kind}.{role}` | Per kind and role — `package/consumes`, `http_route/provides`, and so on. |

---

## The three ways a metric can relate to its evidence

| | |
|---|---|
| **`instances`** | The value *counts* the evidence. 23 means 23 evidence records. |
| **`population`** | The value is a statistic — a median, a slope. The evidence is the **whole population** it was computed over, because a statistic without its distribution is a number you cannot check. |
| **`assertion`** | A judgement (a boolean, a category) whose evidence has no countable relationship to it. |

And two ways it can be complete:

| | |
|---|---|
| **`exhaustive`** | Every evidence item is present. |
| **`truncated`** | A cap was hit. `omittedCount` and `truncationReason` are **required**. |

There is no third option. A report that quietly carries fewer evidence items than its metric
claims is rejected — by the CLI when it writes it, and by the server when it receives it.
