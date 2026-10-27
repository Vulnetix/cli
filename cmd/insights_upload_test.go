package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

func TestPrepareCliInsightsUploadKeepsSmallReportJSON(t *testing.T) {
	req := vdb.CliInsightsRequest{SchemaVersion: "1.0.0"}

	budget, err := prepareCliInsightsUpload(&req, vdb.CliEnv{CliVersion: "test"}, []byte(`{"schemaVersion":"1.0.0"}`))

	require.NoError(t, err)
	require.False(t, budget.ReportJSONOmitted)
	require.Equal(t, `{"schemaVersion":"1.0.0"}`, req.ReportJSON)
	require.LessOrEqual(t, budget.SizeBytes, budget.LimitBytes)
}

func TestPrepareCliInsightsUploadOmitsReportJSONWhenEnvelopeWouldExceedLimit(t *testing.T) {
	req := vdb.CliInsightsRequest{SchemaVersion: "1.0.0"}
	reportBody := []byte(strings.Repeat(`"`, 17*1024*1024))

	budget, err := prepareCliInsightsUpload(&req, vdb.CliEnv{CliVersion: "test"}, reportBody)

	require.NoError(t, err)
	require.True(t, budget.ReportJSONOmitted)
	require.Empty(t, req.ReportJSON)
	require.LessOrEqual(t, budget.SizeBytes, budget.LimitBytes)
}

// The size is computed, not marshalled twice; it must still be the size that is sent.
func TestPrepareCliInsightsUploadSizeIsTheMarshalledSize(t *testing.T) {
	indented := []byte("{\n  \"schemaVersion\": \"1.0.0\",\n  \"note\": \"<a href=\\\"x\\\">&amp;</a>\"\n}")
	cases := map[string]vdb.CliInsightsRequest{
		"empty payload":   {},
		"with fields":     {SchemaVersion: "1.0.0", Diagnostics: []vdb.CliInsightsDiag{{Message: "m"}}},
		"only diagnostic": {Diagnostics: []vdb.CliInsightsDiag{{Message: "m"}}},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			env := vdb.CliEnv{CliVersion: "test"}
			budget, err := prepareCliInsightsUpload(&req, env, indented)
			require.NoError(t, err)
			require.False(t, budget.ReportJSONOmitted)
			raw, err := json.Marshal(cliInsightsRequestEnvelope{Env: env, Payload: &req})
			require.NoError(t, err)
			require.Equal(t, len(raw), budget.SizeBytes)
		})
	}
}

// The artifact is uploaded compacted, and is the same document.
func TestPrepareCliInsightsUploadCompactsTheReport(t *testing.T) {
	indented := []byte("{\n  \"schemaVersion\": \"1.0.0\",\n  \"graph\": {\n    \"nodes\": []\n  }\n}")
	req := vdb.CliInsightsRequest{SchemaVersion: "1.0.0"}
	_, err := prepareCliInsightsUpload(&req, vdb.CliEnv{}, indented)
	require.NoError(t, err)
	require.Equal(t, `{"schemaVersion":"1.0.0","graph":{"nodes":[]}}`, req.ReportJSON)
	require.JSONEq(t, string(indented), req.ReportJSON)
}
