package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/vulnetix/cli/v2/internal/memory"
	"github.com/vulnetix/cli/v2/internal/reachability"
	"github.com/vulnetix/cli/v2/pkg/vdb"
)

// reachabilityEngine is shared across vdb command invocations within a
// single CLI process. It's lazily initialised because building parser
// pools touches CGo state.
var reachabilityEngine = reachability.NewEngine()

// resolveReachabilityMode parses the global --reachability flag, returning
// reachability.ModeBoth on empty input. Invalid values produce a hard
// error so users notice typos rather than silently scanning nothing.
func resolveReachabilityMode() (reachability.Mode, error) {
	mode, ok := reachability.ParseMode(vdbReachability)
	if !ok {
		return "", fmt.Errorf("invalid --reachability %q (expected: direct, transitive, both, off)", vdbReachability)
	}
	return mode, nil
}

// runReachability fetches tree-sitter queries for vulnID and runs them
// against projectRoot, scanning the installed copy of pkg in ecosystem.
//
// Returns nil when the user has disabled reachability (--reachability=off),
// when the API responds with no queries, or when neither v2 is selected
// nor any matches were produced.
//
// Errors from the API or the scanner are returned to the caller so the
// command can decide whether to surface or downgrade them. The function
// never modifies the underlying CVE response payload — the caller is
// responsible for splicing the result into command output.
func runReachability(ctx context.Context, client *vdb.Client, vulnID, ecosystem, pkg string) (*reachability.Result, error) {
	mode, err := resolveReachabilityMode()
	if err != nil {
		return nil, err
	}
	if mode == reachability.ModeOff {
		return nil, nil
	}
	if client.APIVersion != "/v2" {
		// Queries are only published on v2; bail quietly so legacy v1
		// callers don't see surprising errors.
		return nil, nil
	}
	resp, err := client.V2TreeSitterQueries(vulnID, vdb.V2TreeSitterParams{})
	if err != nil {
		// 404 from the tree-sitter endpoint just means there are no
		// queries derived for this vuln yet — common for older or
		// less-popular advisories. Silent skip; the rest of the vuln
		// output is unaffected.
		var nfe *vdb.NotFoundError
		if errors.As(err, &nfe) {
			return &reachability.Result{}, nil
		}
		return nil, err
	}
	if resp == nil || len(resp.Queries) == 0 {
		return &reachability.Result{}, nil
	}
	cwd, _ := os.Getwd()
	req := reachability.ScanRequest{
		ProjectRoot: cwd,
		Ecosystem:   ecosystem,
		Package:     pkg,
		Queries:     resp.Queries,
		Mode:        mode,
	}
	return reachability.Scan(ctx, reachabilityEngine, req)
}

// reachabilityToEvidence converts a scanner result to the memory.yaml
// schema. Returns nil if the result is empty.
func reachabilityToEvidence(r *reachability.Result) *memory.ReachabilityEvidence {
	if r == nil || r.Empty() {
		return nil
	}
	ev := &memory.ReachabilityEvidence{}
	for _, m := range r.Direct {
		ev.Direct = append(ev.Direct, memory.ReachabilityMatch{
			File:  m.File,
			Range: m.Range(),
			Query: m.Query,
		})
	}
	for _, m := range r.Transitive {
		ev.Transitive = append(ev.Transitive, memory.ReachabilityMatch{
			File:  m.File,
			Range: m.Range(),
			Query: m.Query,
		})
	}
	return ev
}

// matchesToMaps turns the typed scanner output into plain maps so the
// pretty-text renderer (which expects JSON-shaped data) can read it
// without reflection.
func matchesToMaps(ms []reachability.Match) []map[string]any {
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		entry := map[string]any{
			"file":       m.File,
			"start_line": m.StartLine,
			"end_line":   m.EndLine,
		}
		if m.Query != "" {
			entry["query"] = m.Query
		}
		if m.Language != "" {
			entry["language"] = m.Language
		}
		if len(m.Captures) > 0 {
			entry["captures"] = m.Captures
		}
		out = append(out, entry)
	}
	return out
}

// extractEcoPkg pulls the best-effort (ecosystem, package) pair out of
// the loose CVE response body. CVE schemas vary across sources; this
// function looks at the common shapes and returns the first match.
// Empty strings are returned when nothing reliable is found — the
// scanner gracefully falls back to a transitive-only run.
func extractEcoPkg(data any) (string, string) {
	m, ok := data.(map[string]any)
	if !ok {
		return "", ""
	}
	// Top-level affected[] (OSV-flavoured) is the most reliable source.
	if aff, ok := m["affected"].([]any); ok {
		for _, entry := range aff {
			em, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if pkg, ok := em["package"].(map[string]any); ok {
				name, _ := pkg["name"].(string)
				eco, _ := pkg["ecosystem"].(string)
				if name != "" {
					return eco, name
				}
			}
		}
	}
	// Vulnetix-normalised shape: x_affected[].purl / x_affected[].name.
	if xa, ok := m["x_affected"].([]any); ok {
		for _, entry := range xa {
			em, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			name, _ := em["name"].(string)
			eco, _ := em["ecosystem"].(string)
			if name != "" {
				return eco, name
			}
		}
	}
	return "", ""
}

// attachReachability merges the reachability output block into the CVE
// response payload. When the payload is a map (the usual case) the
// block is added under "x_reachability"; otherwise the payload is
// rewrapped into a {"data": ..., "x_reachability": ...} shape so the
// information is never lost in JSON output.
func attachReachability(dst *any, block map[string]any) {
	if dst == nil || block == nil {
		return
	}
	if m, ok := (*dst).(map[string]any); ok {
		m["x_reachability"] = block
		return
	}
	*dst = map[string]any{
		"data":           *dst,
		"x_reachability": block,
	}
}

// reachabilityToOutputMap converts a scanner result to the structure
// inserted into JSON/YAML CLI output. Returns nil when there is nothing
// useful to emit so consumers don't see empty arrays everywhere.
func reachabilityToOutputMap(r *reachability.Result) map[string]any {
	if r == nil || (r.Empty() && r.SkippedDirect == "" && r.SkippedTransitive == "") {
		return nil
	}
	out := map[string]any{
		"queries_run": r.QueriesRun,
	}
	if len(r.Direct) > 0 {
		out["direct"] = matchesToMaps(r.Direct)
	}
	if len(r.Transitive) > 0 {
		out["transitive"] = matchesToMaps(r.Transitive)
	}
	if r.SkippedDirect != "" {
		out["skipped_direct"] = r.SkippedDirect
	}
	if r.SkippedTransitive != "" {
		out["skipped_transitive"] = r.SkippedTransitive
	}
	return out
}
