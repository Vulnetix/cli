package analyze

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The translation must carry the graph, the metrics AND the evidence. A request that carries only
// the report is the bug this whole change exists to fix: the server persists from these fields and
// from nothing else, so anything missing here is a row that never gets written.
func TestToWire_CarriesEverythingTheServerPersistsFrom(t *testing.T) {
	b := newTestBuilder()

	ref := b.AddFile(&FileRecord{ID: "file-main.go", Type: "file", Path: "main.go", Language: "go"})
	b.Count(Metric{ID: "business.files.source", Family: "business", Name: "Source files",
		Definition: "Files with a recognised source language."}, []EvidenceRef{ref})

	r, _, err := b.Finish(time.Now())
	require.NoError(t, err)

	r.Graph = &Graph{
		Nodes: []Node{{ID: "file:main.go", Kind: "file", Name: "main.go", Path: "main.go"}},
		Edges: []Edge{{ID: "e1", Kind: "contains", From: "repo", To: "file:main.go", Confidence: 1}},
		CrossRepoEdges: []CrossRepoEdge{{
			ID: "x1", LocalNodeID: "dep:acme", JoinKind: "package", JoinKey: "pkg:golang/acme",
			Role: "consumes", Confidence: 0.9,
		}},
	}

	req, err := ToWire(r)
	require.NoError(t, err)

	require.Len(t, req.Graph.Nodes, 1)
	require.Len(t, req.Graph.Edges, 1)
	require.Len(t, req.Graph.CrossRepoEdges, 1)
	require.Len(t, req.Metrics, 1)
	require.Len(t, req.Evidence.Records, 1, "the record store must travel with the metrics that cite it")

	m := req.Metrics[0]
	require.Equal(t, float64(1), m.Value)
	require.Len(t, m.EvidenceRefs, 1)
	require.Equal(t, "file-main.go", m.EvidenceRefs[0].RecordID)

	// The server compares these lower-case and rejects the submission if they are not.
	require.Equal(t, "instances", m.EvidenceSemantics)
	require.Equal(t, "exhaustive", m.EvidenceCompleteness)

	var rec map[string]any
	require.NoError(t, json.Unmarshal(req.Evidence.Records[0], &rec))
	require.Equal(t, "file-main.go", rec["id"])
	require.Equal(t, "file", rec["type"], "the record store is discriminated on type; a missing one is rejected")
}

// A metric we could not measure is null on the wire, as it is in the report. Sending 0 would tell
// the database we looked and found none.
func TestToWire_UnmeasuredStaysNull(t *testing.T) {
	b := newTestBuilder()
	b.Unmeasured(Metric{ID: "activity.issues.total", Family: "activity", Name: "Issues",
		Definition: "Issues in the window."}, "no GitHub access")

	r, _, err := b.Finish(time.Now())
	require.NoError(t, err)

	req, err := ToWire(r)
	require.NoError(t, err)
	require.Nil(t, req.Metrics[0].Value)
	require.Empty(t, req.Metrics[0].EvidenceRefs)
	require.Len(t, req.Diagnostics, 1, "and the reason travels with it")
}

// An unresolved edge has no confidence, not a confidence of zero. Zero would read as "resolved,
// and we trust it not at all" — a different and worse claim.
func TestToWire_ZeroConfidenceIsAbsentNotZero(t *testing.T) {
	require.Nil(t, confidence(0))
	require.NotNil(t, confidence(0.5))
	require.InDelta(t, 0.5, *confidence(0.5), 1e-9)
}
