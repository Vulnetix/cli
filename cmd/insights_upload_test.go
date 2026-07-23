package cmd

import (
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
