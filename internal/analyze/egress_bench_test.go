package analyze

import (
	"os"
	"testing"
)

// How long the collector takes over a real tree. Run with:
//
//	EGRESS_BENCH_ROOT=../.. go test ./internal/analyze -run TestEgressCost -v
//
// Skipped by default: it walks a whole repository and the number means nothing
// on a machine under load, so it is a measurement tool rather than a gate.
func TestEgressCost(t *testing.T) {
	root := os.Getenv("EGRESS_BENCH_ROOT")
	if root == "" {
		t.Skip("EGRESS_BENCH_ROOT not set")
	}

	st := collectEgress(root, nil)
	t.Logf("hosts=%d filesScanned=%d truncated=%v", len(st.hosts), st.filesScanned, st.truncated)
}

func BenchmarkCollectEgress(b *testing.B) {
	root := os.Getenv("EGRESS_BENCH_ROOT")
	if root == "" {
		b.Skip("EGRESS_BENCH_ROOT not set")
	}

	for b.Loop() {
		collectEgress(root, nil)
	}
}
