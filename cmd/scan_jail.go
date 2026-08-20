package cmd

import (
	"context"
	"fmt"
	"sort"
)

// ─────────────────────────────────────────────────────────────────────────
// scan_jail.go — composing the jail gate into the scan family.
//
// `scan --jail` (and the same flag on sca/sast/secrets/containers/iac) runs the
// scan, uploads it, and then assesses the repository against the organisation's
// jail policy in one invocation.
//
// This file OWNS no policy logic. It calls runJailPipeline, the jail
// capability's single entry function, exactly as the `jail` command does — the
// scan family stays an orchestrator.
// ─────────────────────────────────────────────────────────────────────────

// finalizedSnapshotList collects the snapshot uuids this scan just created, in
// stable order and without blanks or duplicates.
//
// They are handed to the gate so the server can resolve them from the write
// path. vdb-api reads through a replica; without this hint a scan-then-gate in
// a single invocation can read its own upload as missing coverage and report
// indeterminate on a run that is actually current.
//
// sarifSnapshots is the category → snapshotUuid map postScanSARIF returns. Map
// iteration order is not stable, so it is sorted by category to keep the request
// body deterministic between otherwise identical runs.
func finalizedSnapshotList(scaSnapshot string, sarifSnapshots map[string]string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(scaSnapshot)

	categories := make([]string, 0, len(sarifSnapshots))
	for category := range sarifSnapshots {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	for _, category := range categories {
		add(sarifSnapshots[category])
	}
	return out
}

// runJailPassForScan evaluates the jail policy for a scan that has just
// finished, and translates the verdict into the scan's own gate vocabulary.
//
// Returns the breaches to merge, whether the gate was indeterminate, and a
// transport error if the gate could not be reached at all.
//
// Breached rules become GateBreach entries namespaced `jail:<label>`. The
// existing quality-gate names stay bare, so anything downstream that parses the
// gateResults JSON — the console's coverage report among them — keeps reading
// the same values it always did, with the jail rules distinguishable by prefix.
func runJailPassForScan(ctx context.Context, rootPath string, knownSnapshots []string) ([]GateBreach, bool, error) {
	opts := JailRunOptions{
		Mode:               jailModeAssess,
		RootPath:           rootPath,
		KnownSnapshotUuids: knownSnapshots,
		// Artefacts belong to the `jail` command. A scan that silently wrote
		// jail.vex.json alongside its own SBOM would surprise anyone reading the
		// .vulnetix directory, and the scan already emits VEX of its own.
		WriteVex:   false,
		WriteSarif: false,
	}

	result, err := runJailPipeline(ctx, opts)
	if err != nil {
		// A verdict that was reached still counts, even if something after it
		// failed; only a gate that never produced one is a transport error.
		if result == nil || result.Response == nil {
			return nil, false, err
		}
	}

	resp := result.Response
	if resp == nil {
		return nil, false, fmt.Errorf("jail returned no verdict")
	}

	// An org with no policy configured must not turn every scan red, or
	// adopting the flag would break every pipeline before a single rule exists.
	if resp.Verdict == "no-policy" {
		return nil, false, nil
	}

	breaches := []GateBreach{}
	indeterminate := false
	for _, r := range resp.Rules {
		switch r.State {
		case "breach":
			breaches = append(breaches, GateBreach{
				Gate:    "jail:" + r.Label,
				Count:   1,
				Message: fmt.Sprintf("jail rule %q breached: %s", r.Label, r.Reason),
			})
		case "indeterminate":
			indeterminate = true
		}
	}

	return breaches, indeterminate, nil
}

// jailIndeterminateError is the exit-3 outcome for a scan whose jail pass could
// not reach a verdict AND which had nothing else to report.
//
// The ordering is deliberate: a breach beats an indeterminate. If one rule is
// definitively violated on data we hold, that is a fact, and an unknown
// elsewhere does not make it less true. Reporting exit 3 there would bury a real
// violation under "we could not tell" and send the operator to look at their CI
// configuration instead of at the vulnerability.
func jailIndeterminateError(breaches []GateBreach, indeterminate bool) error {
	if !indeterminate || len(breaches) > 0 {
		return nil
	}
	return &JailVerdictError{
		Verdict: "indeterminate",
		Code:    ExitIndeterminate,
	}
}
