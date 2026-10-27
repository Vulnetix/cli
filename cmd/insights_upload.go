package cmd

import (
	"bytes"
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

// prepareCliInsightsUpload attaches the report artifact to req when the request still fits
// the API's decompressed size limit, and reports the size it will be.
//
// The artifact is the report compacted: the indented form on disk is about a third larger,
// and as a JSON string every quote in it is escaped again. The request is marshalled once
// without the artifact, and the artifact's escaped length is added to that, so a large graph
// is not marshalled twice just to be measured.
func prepareCliInsightsUpload(req *vdb.CliInsightsRequest, env vdb.CliEnv, reportBody []byte) (cliInsightsUploadBudget, error) {
	budget := cliInsightsUploadBudget{LimitBytes: cliInsightsDecompressedBodyLimitBytes}
	if req == nil {
		return budget, fmt.Errorf("cli.insights request is nil")
	}

	req.ReportJSON = ""
	base, err := json.Marshal(cliInsightsRequestEnvelope{Env: env, Payload: req})
	if err != nil {
		return budget, fmt.Errorf("marshal cli.insights request: %w", err)
	}
	budget.SizeBytes = len(base)
	if len(base) > cliInsightsDecompressedBodyLimitBytes {
		return budget, fmt.Errorf("cli.insights request is %s decompressed, over the API limit of %s",
			formatByteSize(len(base)), formatByteSize(cliInsightsDecompressedBodyLimitBytes))
	}
	if len(reportBody) == 0 {
		return budget, nil
	}

	artifact := reportBody
	var compact bytes.Buffer
	if json.Compact(&compact, reportBody) == nil {
		artifact = compact.Bytes()
	}
	escaped, err := json.Marshal(string(artifact))
	if err != nil {
		return budget, fmt.Errorf("marshal cli.insights report artifact: %w", err)
	}
	size := len(base) + len(`"reportJson":`) + len(escaped)
	if !bytes.Contains(base, []byte(`"payload":{}`)) {
		size++ // the comma before it
	}
	if size > cliInsightsDecompressedBodyLimitBytes {
		budget.ReportJSONOmitted = true
		return budget, nil
	}
	req.ReportJSON = string(artifact)
	budget.SizeBytes = size
	return budget, nil
}

func formatByteSize(bytes int) string {
	const mib = 1024 * 1024
	if bytes >= mib {
		return fmt.Sprintf("%.1f MiB", float64(bytes)/mib)
	}

	return fmt.Sprintf("%d bytes", bytes)
}
