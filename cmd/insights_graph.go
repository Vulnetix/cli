package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/vulnetix/cli/v3/internal/analyze"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// postScannerGraphInsights publishes the tech-stack graph discovered alongside SCA,
// containers, IaC, SAST, secrets and license scans. It is intentionally best-effort:
// scanner results, local artifacts and quality gates remain authoritative even if the
// graph endpoint is unavailable.
func postScannerGraphInsights(rootPath, toolName string, gitCtx *gitctx.GitContext, w io.Writer) {
	if isUnauthenticatedScan() {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	client := newCliClient()
	if client == nil {
		return
	}

	root, err := filepath.Abs(rootPath)
	if err != nil {
		root = rootPath
	}
	opts := analyze.DefaultOptions()
	opts.Path = root
	opts.NoGit = true
	opts.NoTrust = true
	opts.NoForge = true
	opts.Silent = true

	tool := analyze.Tool{
		Name:    toolName,
		Version: version,
		Commit:  commit,
	}
	report, body, err := analyze.RunGraphOnly(tool, opts, nil)
	if err != nil {
		if verbose {
			fmt.Fprintf(w, "  graph insights skipped: %v\n", err)
		}
		return
	}
	if report == nil || report.Graph == nil || (len(report.Graph.Nodes) == 0 && len(report.Graph.CrossRepoEdges) == 0) {
		return
	}

	req, err := analyze.ToWire(report)
	if err != nil {
		if verbose {
			fmt.Fprintf(w, "  graph insights wire conversion skipped: %v\n", err)
		}
		return
	}

	env := envForCliWithGit(gitCtx)
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    toolName,
		ToolVersion: version,
		ToolVendor:  "Vulnetix",
		ToolHash:    commit,
	}

	budget, err := prepareCliInsightsUpload(&req, env, body)
	if err != nil {
		if verbose {
			fmt.Fprintf(w, "  graph insights upload skipped: %v\n", err)
		}
		return
	}
	if verbose && budget.ReportJSONOmitted {
		fmt.Fprintf(w, "  graph insights report artifact omitted from upload (%s request limit)\n", formatByteSize(budget.LimitBytes))
	}

	resp, err := client.CliInsights(env, req)
	if err != nil {
		if verbose {
			fmt.Fprintf(w, "  graph insights upload skipped: %v\n", err)
		}
		return
	}
	if verbose && resp != nil && resp.Data.Insights != nil {
		s := resp.Data.Insights
		fmt.Fprintf(w, "  graph insights stored: %d node(s), %d edge(s), %d cross-repo key(s)\n",
			s.NodesStored, s.EdgesStored, s.CrossRepoEdgesStored)
	}
}
