package analyze

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// How long the graph-only pass (what `vulnetix scan` uploads as graph
// insights) takes over a real tree, and how big its report is. Run with:
//
//	GRAPH_BENCH_ROOT=/path/to/repo go test ./internal/analyze -run TestGraphOnlyCost -v
//
// GRAPH_BENCH_OUT, when set, receives the report with its timings zeroed, so
// two builds can be compared byte for byte. Skipped by default: the time means
// nothing on a machine under load, so it is a measurement tool, not a gate.
func TestGraphOnlyCost(t *testing.T) {
	root := os.Getenv("GRAPH_BENCH_ROOT")
	if root == "" {
		t.Skip("GRAPH_BENCH_ROOT not set")
	}
	opts := DefaultOptions()
	opts.Path, opts.NoGit, opts.NoTrust, opts.NoForge, opts.Silent = root, true, true, true, true
	start := time.Now()
	rep, body, err := RunGraphOnly(Tool{Name: "vulnetix-static-graph", Version: "bench"}, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("graph-only: %s", time.Since(start).Round(time.Millisecond))
	for _, c := range rep.Run.Collectors {
		t.Logf("  %-14s %-9s %6.2fs", c.Name, c.Status, c.DurationSeconds)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		t.Fatal(err)
	}
	t.Logf("report: %d bytes indented, %d compact; nodes=%d edges=%d", len(body), compact.Len(), len(rep.Graph.Nodes), len(rep.Graph.Edges))
	if out := os.Getenv("GRAPH_BENCH_OUT"); out != "" {
		norm, err := normalisedReport(body)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, norm, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// normalisedReport is body with every timestamp and duration zeroed, so two
// runs over the same tree compare equal.
func normalisedReport(body []byte) ([]byte, error) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var zero func(v any)
	zero = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				switch k {
				case "startedAt", "completedAt", "generatedAt":
					x[k] = ""
				case "durationSeconds":
					x[k] = 0
				default:
					zero(e)
				}
			}
		case []any:
			for _, e := range x {
				zero(e)
			}
		}
	}
	zero(doc)
	return json.MarshalIndent(doc, "", "  ")
}
