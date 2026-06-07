# Make SCA "fix information" consistent across all finding views

## Context

The same SCA finding shows **different fix information** depending on where you look,
because three views read three different sources:

| View | File | Source today | Shows for lodash CVE-2018-16487 |
|------|------|--------------|-------------------------------|
| Findings **list** | `FindingRow.vue` (in `vdb-findings.vue`) | persisted `finding.fixVersion` / `isFixable` | **"no fix"** |
| Finding **detail** | `ScaExploitSummary.vue` (in `vdb-scanner-finding.vue`) | `intel.fixAvailability \|\| finding.fixVersion` | **"Fix: not reported"** |
| Snapshot **result** | `ScaRemediationPanel.vue` (in `vdb-scanner-result.vue`) | **live** Safe-Harbour (`useSafeHarbour`) | **"Recommended: 4.17.21"** ✅ |

Two structural causes:
1. The persisted `Finding.fixVersion` is frequently empty (only set when
   `PackageVersionCVE` has a `fixed`/`patched` row at scan time), and **no
   Safe-Harbour recommendation is persisted** — yet the live Safe-Harbour endpoint
   reliably finds one (4.17.21). So list/detail say "no fix" while the live panel proves a fix exists.
2. On the detail page the **Remediation tab isn't even in the SCA tab list**
   (`finding-category.ts:97` omits `'remediation'`), so the rich panel is unreachable there.

**Decision (from the user):** Make every view show the **live Safe-Harbour
recommendation**, fetched **asynchronously after page results render, with loading
indicators** (don't block the initial render; show a spinner in the fix cell until it
resolves) — applied **everywhere fix info is shown**. Live (not persisted) is the source
of truth. Because per-row live calls don't scale (the findings scale-rule forbids
fan-out and there's no batch endpoint), add a **batch** Safe-Harbour endpoint for the
list. Also **investigate the persistence gap** behind the empty `fixVersion`.

Outcome: list, detail, and result all show the same fix (e.g. `4.17.21`), with graceful
loading states, and "No fix" appears only when Safe-Harbour genuinely has no safe version.

## Status — work started; verified by reading (Parts 1–4 DONE)

Code review confirms the implementation already meets the plan:
- **Part 1 (vdb-api batch)** ✅ `internal/handler/safe_harbour_batch.go` + route `main.go:227`.
  Caps at 50, dedupes, resolves aliases (`ResolvePackageNames`), runs **one** bulk
  `fetchVersionVulnData` over the union of names, reuses `computeSafeHarbourVersion`/
  `computeSafeHarbourSummary`, keys results by both `eco:name` and `eco:name:version`.
- **Part 2 (shared FE)** ✅ `useSafeHarbourBatch.ts` (reactive cache + in-flight dedupe +
  `prime`/`get`), `fix-display.ts` (`fixCellState`/`fixCellLabel` — live recommendation wins,
  then persisted `fixVersion`, then `loading`, then `isFixable`, else `none`),
  `useVdbApi.postSafeHarbourBatch`.
- **Part 3 (detail)** ✅ `finding-category.ts:97` adds `'remediation'` to SCA tabs;
  `ScaExploitSummary.vue` fetches live `useSafeHarbour.loadVersions` on mount, shows a
  `VProgressCircular` while loading, renders the recommendation via the shared helper.
- **Part 4 (list)** ✅ `vdb-findings.vue:210` primes SCA packages **after** `entries` load;
  `FindingRow.vue` is SCA-gated, reactive `get()`, spinner-then-label fix cell.

**Remaining to finish the task:**
1. Build/test/lint both repos (incl. the new `*_test` files) — not yet run.
2. **Part 5 persistence investigation** — not yet done (read-only: trace the empty
   `fixVersion` via deployed API / `v2_cli_sca.go`+`cli_persist.go`); fix the persist path
   only if it's a code gap.
3. Close any gaps the build/tests/lint surface.

---

## Part 1 — vdb-api: batch Safe-Harbour endpoint

Reuse the existing engine — `fetchVersionVulnData` (accepts a `[]packageNames`),
`computeSafeHarbourVersion`, `computeSafeHarbourSummary`, `pickRecommendedVersion`
(`internal/handler/safe_harbour.go`) — to serve many packages in **one** request, far
cheaper than N single calls (one set of bulk per-CVE queries for all names).

- New route (mirror the single endpoint registration in `main.go:232,237`):
  `POST /v1/packages/safe-harbour-batch`.
- Request: `{ "packages": [ {"name","ecosystem","currentVersion"}, ... ] }` — cap at ~50
  per request (the list only sends the visible page's unique packages); reject/trim over cap.
- Response: `{ "results": { "<ecosystem>:<name>": { recommendation:{version,reason},
  recommendedVersions:[...], highestScore } } }` (summary only — no full per-version array,
  to keep payload small for a list).
- New handler `internal/handler/safe_harbour_batch.go`: resolve each package's version
  list via the same `safeHarbourVersionList` helper used by
  `v2_cli_sca_insights.go:fillSafeVersionsInsight`, run `fetchVersionVulnData` once over
  the union of names, fold per package with the existing `cliInsightsConcurrency` semaphore,
  return summaries keyed by `eco:name`.
- Tier-gating: keep parity with the single endpoint (not Pro-gated there → batch also open,
  unless the single one gates; match it).

## Part 2 — website: shared fix-display composable + loading UX

- New `src/composables/useSafeHarbourBatch.ts` (Pinia store or module-level reactive cache):
  - `prime(packages: {name,ecosystem,version}[])` → dedupes, fires one
    `useVdbApi().postSafeHarbourBatch(...)` per visible page, writes a reactive cache keyed
    by `eco:name:version`.
  - `get(key) → { loading: boolean, recommendation?: {version,reason} | null }`.
  - In-flight dedupe (mirror `useVdbApi` `inflightGets` pattern) so re-renders don't refetch.
- New API method in `src/composables/useVdbApi.ts`: `postSafeHarbourBatch(packages)` → POST
  to the new route (sibling of `getPackageVersions`).
- New shared display helper `src/lib/utils/fix-display.ts`:
  `fixCellState(finding, batch)` → `'loading' | {version} | 'none'`, consolidating the
  duplicated logic now in `FindingRow.vue`, `ScaExploitSummary.vue`, `ScaRemediationPanel.vue`.
- Loading indicator: reuse the existing skeleton/spinner pattern (`OutputSkeleton` is used by
  `SafeHarbourPicker.vue`; for inline cells use a small `VProgressCircular indeterminate
  size="14"`). Show it while `loading`, then the version chip or a genuine "No fix".

## Part 3 — Finding detail page (cheap, single finding)

- `src/shared/finding-category.ts:97` — add `'remediation'` to the `sca` tab list (e.g. after
  `'reachability'`) so the existing `<ScaRemediationPanel>` section in
  `vdb-scanner-finding.vue:731-748` becomes reachable. (`introducedVia.data` is already passed.)
- `src/components/scanner-results/finding-panels/ScaExploitSummary.vue` — replace the Fix
  signal (`line 52,67`) so it reflects the live recommendation: call `useSafeHarbour.loadVersions`
  (single finding) on mount; while loading show the spinner, then
  `recommendation.version` (e.g. `4.17.21`); fall back to `finding.fixVersion` then "not
  reported" only when Safe-Harbour returns no recommendation. Route through `fix-display.ts`.

## Part 4 — Findings list (lazy batch + loading)

- `vdb-findings.vue` — after `entries` for a page load, compute the unique SCA packages on
  that page and call `useSafeHarbourBatch.prime(...)` (lazy, post-render). Re-prime on
  page/filter change.
- `src/components/findings/FindingRow.vue` — the Fix cell (`lines 125-139, 284-292`) reads
  `fixCellState(finding, batch)`: `loading` → spinner; `{version}` → `v4.17.21` chip;
  `none` → "No fix". Keep the existing `fixVersion`/`isFixable` as an instant first paint, then
  upgrade to the live recommendation when the batch resolves (so the cell is never falsely
  "No fix" once data arrives).

## Part 5 — Persistence investigation (root cause of empty `fixVersion`)

Investigate why `fixVersion` is empty for a finding whose registry fix exists (lodash 4.17.5):
- Trace `v.FixVersion` population in `vdb-api/internal/handler/v2_cli_sca.go:591-617`
  (`PackageVersionCVE` where `relationshipType IN ('fixed','patched')`) and the persist in
  `cli_persist.go insertFindingRow`. Determine whether it's (a) a VDB data-completeness gap
  (no fixed row indexed for that CVE), or (b) the persist path not running the fix query for
  this finding shape (e.g. legacy/community path).
- If it's a code gap, fix the persist path so new scans carry `fixVersion`. Validate against the
  deployed API (DB creds live in ECS, not the repo — per `reference_vdb_api_deploy`). Document
  findings in the PR; no backfill of historical rows is required since display now derives live.

---

## Files
**vdb-api:** C `internal/handler/safe_harbour_batch.go`; M `main.go` (route); reuse `safe_harbour.go`, `v2_cli_sca_insights.go` helpers. (+ Part 5 investigation in `v2_cli_sca.go`/`cli_persist.go`.)
**website:** C `src/composables/useSafeHarbourBatch.ts`, `src/lib/utils/fix-display.ts`; M `src/composables/useVdbApi.ts`, `src/shared/finding-category.ts`, `src/pages/vdb-findings.vue`, `src/components/findings/FindingRow.vue`, `src/components/scanner-results/finding-panels/ScaExploitSummary.vue`, and (optionally) `ScaRemediationPanel.vue` to use the shared helper.

## Verification
- **vdb-api:** `go build ./... && go test ./internal/handler/...`; `curl -XPOST .../v1/packages/safe-harbour-batch` with `{packages:[{name:"lodash",ecosystem:"npm",currentVersion:"4.17.11"}]}` → assert `results["npm:lodash"].recommendation.version` (≈ `4.17.21`). One batch of ~25 packages returns in ~one set of bulk queries.
- **website:** `npm run lint && npm run dev`.
  - List (`/findings`): rows paint immediately; fix cells show a spinner, then resolve to
    `v4.17.21` (lodash) — no row stuck at a false "No fix"; spinner clears on genuine no-fix.
  - Detail (`vdb-scanner-finding`): a **Remediation tab** now appears for SCA; the "Fix"
    decision signal shows `4.17.21` (loading spinner first), matching the result page.
  - Result page unchanged (already correct).
- **Consistency check:** open lodash CVE-2018-16487 in all three views → all show `4.17.21`.
- **Persistence:** capture the root-cause finding for the empty `fixVersion`; if a code fix lands,
  re-scan a lodash fixture against the deployed API and confirm the new Finding row carries `fixVersion`.
