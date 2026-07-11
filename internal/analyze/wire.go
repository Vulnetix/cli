package analyze

// The report, translated into what the API stores.
//
// This translation is the whole feature, and it did not exist: the request type had a field for
// the report and nowhere to put a graph, so every upload stored an empty run. The server persists
// rows from `graph`, `metrics` and `evidence` and from nothing else — it does not read the report
// it is handed, it only files it.
//
// Nothing is invented here and nothing is dropped. A metric's evidence refs travel inside the
// metric, because the server re-checks that the evidence accounts for the value before it writes
// anything, and a metric whose evidence arrived separately could not be checked at all.

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// ToWire turns a report into an insights submission.
func ToWire(r *Report) (vdb.CliInsightsRequest, error) {
	req := vdb.CliInsightsRequest{
		SchemaVersion: r.SchemaVersion,
		Tool: &vdb.CliInsightsTool{
			Name:           r.Tool.Name,
			Version:        r.Tool.Version,
			CatalogVersion: r.Tool.CatalogVersion,
		},
		Target: &vdb.CliInsightsTarget{
			RepoID:        r.Target.RepoID,
			OrgKey:        r.Target.OrgKey,
			RemoteURL:     r.Target.RemoteURL,
			DefaultBranch: r.Target.DefaultBranch,
			HeadCommit:    r.Target.HeadCommit,
		},
	}

	if w := r.Run.HistoryWindow; w != nil {
		req.Run = &vdb.CliInsightsRunMeta{
			HistoryWindow: &vdb.CliInsightsWindow{
				Since:         epochMillis(w.Since),
				Until:         epochMillis(w.Until),
				CommitsWalked: w.CommitsWalked,
				CommitLimit:   w.CommitLimit,
			},
		}
	}

	for _, d := range r.Diagnostics {
		req.Diagnostics = append(req.Diagnostics, vdb.CliInsightsDiag{
			Level:     d.Level,
			Collector: d.Collector,
			MetricID:  d.MetricID,
			Message:   d.Message,
			Caveat:    d.Caveat,
		})
	}

	if r.Graph != nil {
		req.Graph = graphToWire(r.Graph)
	}

	req.Metrics = metricsToWire(r.Metrics)

	if r.Evidence != nil && len(r.Evidence.Records) > 0 {
		records := make([]json.RawMessage, 0, len(r.Evidence.Records))
		for i, rec := range r.Evidence.Records {
			raw, err := json.Marshal(rec)
			if err != nil {
				return req, fmt.Errorf("marshal evidence record %d: %w", i, err)
			}
			records = append(records, raw)
		}
		req.Evidence = &vdb.CliInsightsEvidenceIn{Records: records}
	}

	return req, nil
}

func graphToWire(g *Graph) *vdb.CliInsightsGraph {
	out := &vdb.CliInsightsGraph{
		Nodes:          make([]vdb.CliInsightsNode, 0, len(g.Nodes)),
		Edges:          make([]vdb.CliInsightsEdge, 0, len(g.Edges)),
		CrossRepoEdges: make([]vdb.CliInsightsCrossRepoEdge, 0, len(g.CrossRepoEdges)),
	}

	for i := range g.Nodes {
		n := &g.Nodes[i]
		out.Nodes = append(out.Nodes, vdb.CliInsightsNode{
			ID:            n.ID,
			Kind:          n.Kind,
			Name:          n.Name,
			QualifiedName: n.QualifiedName,
			Path:          n.Path,
			StartLine:     n.StartLine,
			EndLine:       n.EndLine,
			Language:      n.Language,
			Purl:          n.Purl,
			Exported:      n.Exported,
			Properties:    properties(n.Properties),
		})
	}

	for i := range g.Edges {
		e := &g.Edges[i]
		out.Edges = append(out.Edges, vdb.CliInsightsEdge{
			ID:         e.ID,
			Kind:       e.Kind,
			From:       e.From,
			To:         e.To,
			Confidence: confidence(e.Confidence),
			Resolution: e.Resolution,
			Properties: properties(e.Properties),
		})
	}

	for i := range g.CrossRepoEdges {
		c := &g.CrossRepoEdges[i]
		out.CrossRepoEdges = append(out.CrossRepoEdges, vdb.CliInsightsCrossRepoEdge{
			ID:             c.ID,
			LocalNodeID:    c.LocalNodeID,
			JoinKind:       c.JoinKind,
			JoinKey:        c.JoinKey,
			Role:           c.Role,
			TargetRepoHint: c.TargetRepoHint,
			Confidence:     confidence(c.Confidence),
			Properties:     properties(c.Properties),
		})
	}

	return out
}

func metricsToWire(metrics []Metric) []vdb.CliInsightsMetric {
	out := make([]vdb.CliInsightsMetric, 0, len(metrics))

	for i := range metrics {
		m := &metrics[i]
		w := vdb.CliInsightsMetric{
			ID:         m.ID,
			Family:     m.Family,
			Name:       m.Name,
			Definition: m.Definition,
			Unit:       m.Unit,
			Statistic:  m.Statistic,
			// nil stays nil. A metric we could not measure must not arrive as a zero.
			Value:                m.Value,
			EvidenceSemantics:    m.EvidenceSemantics,
			EvidenceCompleteness: m.EvidenceCompleteness,
			PopulationSize:       m.PopulationSize,
			OmittedCount:         m.OmittedCount,
			TruncationReason:     m.TruncationReason,
			EvidenceRefs:         make([]vdb.CliInsightsEvidenceRef, 0, len(m.EvidenceRefs)),
		}

		if m.Window != nil {
			w.Window = &vdb.CliInsightsMetricWindow{
				Since: epochMillis(m.Window.Since),
				Until: epochMillis(m.Window.Until),
				Label: m.Window.Label,
			}
		}
		if m.Classification != nil {
			w.Classification = &vdb.CliInsightsClassif{
				Label:      m.Classification.Label,
				Thresholds: m.Classification.Thresholds,
			}
		}

		for j := range m.EvidenceRefs {
			w.EvidenceRefs = append(w.EvidenceRefs, evidenceRefToWire(&m.EvidenceRefs[j]))
		}

		out = append(out, w)
	}

	return out
}

func evidenceRefToWire(r *EvidenceRef) vdb.CliInsightsEvidenceRef {
	return vdb.CliInsightsEvidenceRef{
		Kind:           r.Kind,
		RunIndex:       r.RunIndex,
		ResultIndex:    r.ResultIndex,
		StatementIndex: r.StatementIndex,
		BomRef:         r.BomRef,
		SpdxID:         r.SpdxID,
		Check:          r.Check,
		DetailIndex:    r.DetailIndex,
		RecordID:       r.RecordID,
	}
}

func properties(p map[string]any) json.RawMessage {
	if len(p) == 0 {
		return nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		// Properties are decoration — a node's kind, name and path are what the graph is drawn
		// from. Losing an unserialisable property is not worth losing the node it hangs off.
		return nil
	}

	return raw
}

// confidence sends nothing rather than zero. A confidence of 0 means "we did not resolve this",
// and storing it as the number 0.0 would make an unresolved edge look like a maximally distrusted
// one — a different claim, and a worse one.
func confidence(c float64) *float64 {
	if c == 0 {
		return nil
	}

	return &c
}

// epochMillis converts a report timestamp (RFC 3339) to what the database stores (epoch ms).
// An unparseable or absent timestamp is 0, which the server treats as absent.
func epochMillis(ts string) int64 {
	if ts == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0
	}

	return t.UnixMilli()
}
