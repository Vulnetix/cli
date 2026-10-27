package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vulnetix/cli/v3/internal/analyze"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// postScannerGraphInsights publishes the tech-stack graph discovered alongside SCA,
// containers, IaC, SAST, secrets and license scans. It is intentionally best-effort:
// scanner results, local artifacts and quality gates remain authoritative even if the
// graph endpoint is unavailable.
func postScannerGraphInsights(rootPath, toolName string, gitCtx *gitctx.GitContext, w io.Writer) {
	finishScannerGraphInsights(startScannerGraphInsights(context.Background(), rootPath, toolName, gitCtx, 0, false), w)
}

// scannerGraph is the graph insights request, built and ready to send.
type scannerGraph struct {
	client *vdb.Client
	env    vdb.CliEnv
	req    vdb.CliInsightsRequest
	// notes are the verbose lines written while building it, held so they print at the join
	// rather than through the progress display of whatever ran alongside.
	notes bytes.Buffer
}

// startScannerGraphInsights builds the graph insights concurrently with the rest of the scan.
// The graph reads only the tree, so it can run while SAST evaluates; the scan joins it with
// finishScannerGraphInsights where it used to build it. workers bounds its parallelism (0 is
// every core) and noCache turns off the per-file graph cache. A nil future means there is
// nothing to send: an unauthenticated scan, or no API client.
func startScannerGraphInsights(ctx context.Context, rootPath, toolName string, gitCtx *gitctx.GitContext, workers int, noCache bool) *future[*scannerGraph] {
	if isUnauthenticatedScan() {
		return nil
	}
	client := newCliClient()
	if client == nil {
		return nil
	}
	return startFuture(func() *scannerGraph {
		return buildScannerGraph(ctx, client, rootPath, toolName, gitCtx, workers, noCache)
	})
}

func buildScannerGraph(ctx context.Context, client *vdb.Client, rootPath, toolName string, gitCtx *gitctx.GitContext, workers int, noCache bool) *scannerGraph {
	g := &scannerGraph{client: client}
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
	opts.Workers = workers
	opts.Context = ctx
	opts.CacheDir = graphCacheDir(noCache)
	opts.CacheSalt = sastCacheSalt()

	tool := analyze.Tool{
		Name:    toolName,
		Version: version,
		Commit:  commit,
	}
	report, body, err := analyze.RunGraphOnly(tool, opts, nil)
	if err != nil {
		if verbose {
			fmt.Fprintf(&g.notes, "  graph insights skipped: %v\n", err)
		}
		return g
	}
	if report == nil || report.Graph == nil || (len(report.Graph.Nodes) == 0 && len(report.Graph.CrossRepoEdges) == 0) {
		return g
	}

	req, err := analyze.ToWire(report)
	if err != nil {
		if verbose {
			fmt.Fprintf(&g.notes, "  graph insights wire conversion skipped: %v\n", err)
		}
		return g
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
			fmt.Fprintf(&g.notes, "  graph insights upload skipped: %v\n", err)
		}
		return g
	}
	if verbose && budget.ReportJSONOmitted {
		fmt.Fprintf(&g.notes, "  graph insights report artifact omitted from upload (%s request limit)\n", formatByteSize(budget.LimitBytes))
	}
	g.env, g.req = env, req
	return g
}

// finishScannerGraphInsights waits for the graph, prints what building it said, and sends it
// in the background.
func finishScannerGraphInsights(f *future[*scannerGraph], w io.Writer) {
	g := f.get()
	if g == nil {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	_, _ = w.Write(g.notes.Bytes())
	if g.req.Graph == nil {
		return
	}
	env, req, client := g.env, g.req, g.client
	goBackground(w, func(w io.Writer) {
		resp, err := client.CliInsightsDeferred(env, req)
		if err != nil {
			if verbose {
				fmt.Fprintf(w, "  graph insights upload skipped: %v\n", err)
			}
			return
		}
		if verbose && resp != nil && resp.Data.Deferred {
			fmt.Fprintln(w, "  graph insights accepted, stored after the answer")
		}
		if verbose && resp != nil && resp.Data.Insights != nil {
			s := resp.Data.Insights
			fmt.Fprintf(w, "  graph insights stored: %d node(s), %d edge(s), %d cross-repo key(s)\n",
				s.NodesStored, s.EdgesStored, s.CrossRepoEdgesStored)
		}
	})
}

// graphWorkersBesideSAST is how many files the graph reads at once while SAST evaluates on
// the same cores: a quarter of them, so the graph finishes alongside SAST rather than
// slowing it down.
func graphWorkersBesideSAST() int {
	return max(1, runtime.GOMAXPROCS(0)/4)
}

// graphCacheDir is where the per-file graph cache lives (internal/analyze graph_cache.go), or
// "" when it is off. VULNETIX_GRAPH_CACHE_DIR moves it, for a CI cache step.
func graphCacheDir(off bool) string {
	if off {
		return ""
	}
	if d := os.Getenv("VULNETIX_GRAPH_CACHE_DIR"); d != "" {
		return d
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "vulnetix", "graph")
}
