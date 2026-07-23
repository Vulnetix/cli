package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

const cliInsightsDecompressedBodyLimitBytes = 32 << 20

type cliInsightsUploadBudget struct {
	SizeBytes         int
	LimitBytes        int
	ReportJSONOmitted bool
}

type cliInsightsRequestEnvelope struct {
	Env     vdb.CliEnv              `json:"env"`
	Payload *vdb.CliInsightsRequest `json:"payload,omitempty"`
}

func prepareCliInsightsUpload(req *vdb.CliInsightsRequest, env vdb.CliEnv, reportBody []byte) (cliInsightsUploadBudget, error) {
	budget := cliInsightsUploadBudget{LimitBytes: cliInsightsDecompressedBodyLimitBytes}
	if req == nil {
		return budget, fmt.Errorf("cli.insights request is nil")
	}

	if len(reportBody) > 0 {
		req.ReportJSON = string(reportBody)
	}
	size, err := cliInsightsEnvelopeSize(env, req)
	if err != nil {
		return budget, err
	}
	budget.SizeBytes = size
	if size <= cliInsightsDecompressedBodyLimitBytes {
		return budget, nil
	}

	if req.ReportJSON != "" {
		req.ReportJSON = ""
		size, err = cliInsightsEnvelopeSize(env, req)
		if err != nil {
			return budget, err
		}
		budget.SizeBytes = size
		budget.ReportJSONOmitted = true
		if size <= cliInsightsDecompressedBodyLimitBytes {
			return budget, nil
		}
	}

	return budget, fmt.Errorf("cli.insights request is %s decompressed, over the API limit of %s",
		formatByteSize(size), formatByteSize(cliInsightsDecompressedBodyLimitBytes))
}

func cliInsightsEnvelopeSize(env vdb.CliEnv, req *vdb.CliInsightsRequest) (int, error) {
	raw, err := json.Marshal(cliInsightsRequestEnvelope{Env: env, Payload: req})
	if err != nil {
		return 0, fmt.Errorf("marshal cli.insights request: %w", err)
	}

	return len(raw), nil
}

func formatByteSize(bytes int) string {
	const mib = 1024 * 1024
	if bytes >= mib {
		return fmt.Sprintf("%.1f MiB", float64(bytes)/mib)
	}

	return fmt.Sprintf("%d bytes", bytes)
}
