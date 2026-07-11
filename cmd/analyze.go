package cmd

// `vulnetix analyze` — the org tech-stack graph and the evidence-backed repo report.
//
// Two outputs, one command:
//
//	1. A graph of this repository's tech stack, plus the cross-repo join keys that let an
//	   org-wide graph be assembled from N of these runs. The command never reads a second
//	   repository; it publishes what this one provides and consumes, and the server matches
//	   them up.
//
//	2. Metrics — business, security, quality, maintainability, trust, activity — each one
//	   carrying the evidence that produced it. A metric of 23 references 23 evidence items,
//	   or it declares how many it dropped and why. The report is validated against
//	   schemas/vulnetix-analyze-report.schema.json before it is written or uploaded, so a
//	   report we would reject on the way in is one we cannot produce on the way out.
//
// The upload route is /v2/cli.insights, not /v2/cli.analyze — that one already belongs to
// ELF binary analysis.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/analyze"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [path]",
	Short: "Build the repository's tech-stack graph and its evidence-backed metrics",
	Long: `Analyze builds a graph of this repository's tech stack and reports business,
security, quality, maintainability, trustworthiness and activity metrics for it.

Every metric carries the evidence that produced it. If a metric's value is 23, the report
contains 23 evidence records; if a cap was hit, the report says how many items it dropped
and why. A metric that could not be measured is null, never zero — "we found no secrets"
and "we could not look for secrets" are different claims and stay different.

The graph includes cross-repo join keys: what this repository provides, and what it
consumes. The scan never reads another repository. An org-wide graph is assembled by
matching one repo's provides against another's consumes, so running this in every repo's
CI produces the whole picture without any of them needing access to the others.

GitHub authentication
  Review coverage, pull-request response times, and whether commits reached the default
  branch unreviewed do not exist in the git repository — they live in GitHub. analyze
  checks for credentials before it starts scanning, and stops if it cannot find any:

    GITHUB_TOKEN    already set for you inside GitHub Actions
    GH_TOKEN
    gh auth login   the gh CLI's own credentials are used if neither variable is set

  Pass --no-forge to skip these metrics. They are then reported as "not measured" rather
  than zero, because "we found no unreviewed commits" and "we did not look" are different
  claims and this report will not conflate them.

  A repository whose remote is not GitHub skips the check automatically.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAnalyze,
}

func init() {
	analyzeCmd.Flags().String("path", ".", "Directory to analyze")
	analyzeCmd.Flags().Int("window-days", 365, "How far back to walk history")
	analyzeCmd.Flags().Int("max-commits", 20000, "Cap on commits walked; when hit, the report declares it")
	analyzeCmd.Flags().Int("complexity-threshold", 15, "Cyclomatic complexity at which a file counts as highly complex")
	analyzeCmd.Flags().StringP("output", "o", "pretty", "Terminal output format: pretty, json")
	analyzeCmd.Flags().String("output-file", "", "Where to write the report (default: <path>/.vulnetix/analyze.report.json)")
	analyzeCmd.Flags().Bool("no-git", false, "Skip the history walk (activity, contributor and ownership metrics are then absent, not zero)")
	analyzeCmd.Flags().Bool("no-files", false, "Skip the file and complexity pass")
	analyzeCmd.Flags().Bool("no-deps", false, "Skip the dependency pass (and therefore the cross-repo package edges)")
	analyzeCmd.Flags().Bool("no-trust", false, "Skip the open-source policy checks")
	analyzeCmd.Flags().Bool("no-forge", false, "Skip GitHub entirely. Pull-request, review and issue metrics are then reported as not measured, never as zero")
	analyzeCmd.Flags().Bool("no-upload", false, "Do not submit the report (it is submitted automatically when authenticated)")

	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	dctx := display.FromCommand(cmd)

	opts := analyze.DefaultOptions()
	opts.Path, _ = cmd.Flags().GetString("path")
	if len(args) == 1 {
		opts.Path = args[0]
	}
	opts.WindowDays, _ = cmd.Flags().GetInt("window-days")
	opts.MaxCommits, _ = cmd.Flags().GetInt("max-commits")
	opts.ComplexityThreshold, _ = cmd.Flags().GetInt("complexity-threshold")
	opts.NoGit, _ = cmd.Flags().GetBool("no-git")
	opts.NoFiles, _ = cmd.Flags().GetBool("no-files")
	opts.NoDeps, _ = cmd.Flags().GetBool("no-deps")
	opts.NoTrust, _ = cmd.Flags().GetBool("no-trust")
	opts.NoForge, _ = cmd.Flags().GetBool("no-forge")

	outputFile, _ := cmd.Flags().GetString("output-file")
	noUpload, _ := cmd.Flags().GetBool("no-upload")
	silent, _ := cmd.Flags().GetBool("silent")
	opts.Silent = silent

	tool := analyze.Tool{
		Name:    "vulnetix-analyze",
		Version: version,
		Commit:  commit,
	}

	// Registry metadata for dependency staleness. Only available when authenticated — and when
	// it is not, the staleness metrics are null with a reason rather than zero.
	opts.Enrich = packageEnricher()

	// The GitHub check runs before any scanning. Finding out after five minutes of work that a
	// third of the report is null because a token was missing wastes the user's time twice:
	// once now, and once when they have to run it again.
	//
	// It runs before the progress bar starts, because it prints its own line and a live
	// progress line would fight it for the last row of the terminal.
	pre, err := analyze.Check(cmd.Context(), opts)
	if err != nil {
		return err
	}

	// analyze walks history, parses every file, samples complexity across commits and makes a
	// few hundred GitHub calls. On a large repository that is minutes, and minutes of silence is
	// indistinguishable from a hang.
	progress := dctx.Progress("Analyzing "+pre.Target.RepoID, analyze.TotalSteps)
	opts.Progress = &progressReporter{p: progress}

	report, body, err := analyze.Run(tool, opts, pre)
	if err != nil {
		progress.Fail("Analysis failed")

		return err
	}
	progress.Complete("Analyzed " + pre.Target.RepoID)

	root, _ := filepath.Abs(opts.Path)
	outFile := outputFile
	if outFile == "" {
		outFile = filepath.Join(root, ".vulnetix", "analyze.report.json")
	}
	if err := writeAnalyzeReport(outFile, body); err != nil {
		return err
	}
	if !silent {
		fmt.Fprintf(os.Stderr, "Wrote analysis report to %s\n", outFile)
	}

	if !noUpload {
		uploadInsights(cmd, report, body, silent)
	}

	return dctx.Render(report, func(_ interface{}, ctx *display.Context) string {
		return renderAnalyze(ctx, report)
	})
}

// progressReporter adapts display.Progress to the interface the collectors call. The analyze
// package deliberately knows nothing about terminals, so the coupling lives here.
type progressReporter struct{ p *display.Progress }

func (r *progressReporter) Stage(msg string) { r.p.SetStage(msg) }

func (r *progressReporter) Step(done int, msg string) { r.p.Update(done, msg) }

// packageEnricher returns a function that asks the API for registry metadata about a batch of
// PURLs, or nil when the user is not authenticated.
//
// It calls /v2/cli.package-insights and not /v2/cli.sca. Both know the answer; only one of them
// persists a ScannerRun and an IngestionSnapshot as a side effect, and asking what a package's
// publish date is must not fabricate a security scan nobody ran.
func packageEnricher() analyze.EnrichFunc {
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil || auth.IsCommunity(creds) {
		return nil
	}

	return func(purls []string) (map[string]analyze.PackageInsight, error) {
		client := vdb.NewClientFromCredentials(creds)
		client.APIVersion = "/v2"
		client.HTTPClient.Timeout = 120 * time.Second

		resp, err := client.CliPackageInsights(envForCli(), vdb.CliPackageInsightsRequest{
			Purls: purls,
			Options: vdb.CliSCAOptionsLite{
				IncludeCooldown:   true,
				IncludeVersionLag: true,
				IncludeEOL:        true,
			},
		})
		if err != nil {
			return nil, err
		}

		out := make(map[string]analyze.PackageInsight, len(resp.Data.InsightsByPurl))
		for purl, ins := range resp.Data.InsightsByPurl {
			pi := analyze.PackageInsight{
				Purl:        purl,
				PublishedAt: ins.PublishedAt,
				IsEOL:       ins.IsEOL,
			}
			for _, v := range ins.LatestVersions {
				pi.Versions = append(pi.Versions, analyze.VersionStamp{
					Version:     v.Version,
					PublishedAt: v.PublishedAt,
				})
			}
			if len(pi.Versions) > 0 {
				pi.LatestVersion = pi.Versions[0].Version
			}
			if ins.SafeHarbour != nil && ins.SafeHarbour.Recommendation != nil {
				pi.Recommended = ins.SafeHarbour.Recommendation.Version
			}
			out[purl] = pi
		}

		return out, nil
	}
}

func writeAnalyzeReport(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	return os.WriteFile(path, body, 0o644)
}

// uploadInsights submits the report. Best-effort, exactly like aibom, cbom and malscan: an
// upload failure never fails the command, because the report on disk is the authoritative
// artefact and a CI job should not go red because the network did.
func uploadInsights(cmd *cobra.Command, report *analyze.Report, body []byte, silent bool) {
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil || auth.IsCommunity(creds) {
		return
	}

	verbose, _ := cmd.Flags().GetBool("verbose")

	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	client.HTTPClient.Timeout = 180 * time.Second

	git := gitctx.Collect(report.Target.RootPath)
	env := envForCliWithGit(git)
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    "vulnetix-analyze",
		ToolVersion: version,
		ToolVendor:  "Vulnetix",
		ToolHash:    commit,
	}

	req := vdb.CliInsightsRequest{
		SchemaVersion: report.SchemaVersion,
		Tool: &vdb.CliInsightsTool{
			Name:           report.Tool.Name,
			Version:        report.Tool.Version,
			CatalogVersion: report.Tool.CatalogVersion,
		},
		Target: &vdb.CliInsightsTarget{
			RepoID:        report.Target.RepoID,
			OrgKey:        report.Target.OrgKey,
			RemoteURL:     report.Target.RemoteURL,
			DefaultBranch: report.Target.DefaultBranch,
			HeadCommit:    report.Target.HeadCommit,
		},
		ReportJSON: string(body),
	}
	if w := report.Run.HistoryWindow; w != nil {
		req.Run = &vdb.CliInsightsRunMeta{HistoryWindow: &vdb.CliInsightsWindow{
			Since:         epochMillis(w.Since),
			Until:         epochMillis(w.Until),
			CommitsWalked: w.CommitsWalked,
			CommitLimit:   w.CommitLimit,
		}}
	}

	resp, err := client.CliInsights(env, req)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "insights upload failed: %v\n", err)
		}

		return
	}
	if resp != nil && resp.Data.Insights != nil && resp.Data.Insights.URL != "" && !silent {
		fmt.Fprintf(os.Stderr, "Analysis: %s\n", resp.Data.Insights.URL)
	}
}

func epochMillis(rfc3339 string) int64 {
	if rfc3339 == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return 0
	}

	return t.UnixMilli()
}

// renderAnalyze prints the report. Metrics are grouped by family, and a metric that could not
// be measured says so rather than showing a zero — the terminal is the last place that
// distinction can be lost, and losing it there would undo the whole point.
func renderAnalyze(dctx *display.Context, r *analyze.Report) string {
	var b strings.Builder
	term := dctx.Term

	b.WriteString(display.Header(term, "Repository analysis"))
	b.WriteString("\n")
	fmt.Fprintf(&b, "  %s\n", r.Target.RepoID)
	if r.Graph != nil {
		fmt.Fprintf(&b, "  %d nodes, %d edges, %d cross-repo keys\n",
			len(r.Graph.Nodes), len(r.Graph.Edges), len(r.Graph.CrossRepoEdges))
	}
	if w := r.Run.HistoryWindow; w != nil && w.CommitsWalked > 0 {
		fmt.Fprintf(&b, "  %d commits walked\n", w.CommitsWalked)
	}
	b.WriteString("\n")

	families := []string{"activity", "quality", "maintainability", "security", "trust", "business", "graph"}
	byFamily := map[string][]analyze.Metric{}
	for _, m := range r.Metrics {
		byFamily[m.Family] = append(byFamily[m.Family], m)
	}

	for _, fam := range families {
		ms := byFamily[fam]
		if len(ms) == 0 {
			continue
		}
		sort.Slice(ms, func(i, j int) bool { return ms[i].ID < ms[j].ID })

		b.WriteString(display.Subheader(term, strings.ToUpper(fam[:1])+fam[1:]))
		b.WriteString("\n")

		rows := make([][]string, 0, len(ms))
		for _, m := range ms {
			rows = append(rows, []string{
				m.Name,
				formatMetricValue(m),
				formatEvidence(m),
				classificationOf(m),
			})
		}
		b.WriteString(display.Table(term, []display.Column{
			{Header: "Metric"},
			{Header: "Value", Align: display.AlignRight},
			{Header: "Evidence", Align: display.AlignRight},
			{Header: "Status"},
		}, rows))
		b.WriteString("\n")
	}

	// Anything that degraded the run is printed, not buried. A green report from a collector
	// that never ran is worse than a red one.
	if len(r.Diagnostics) > 0 {
		b.WriteString(display.Subheader(term, "Caveats"))
		b.WriteString("\n")
		for _, d := range r.Diagnostics {
			mark := display.Muted(term, "note")
			if d.Level == "warning" {
				mark = "warn"
			} else if d.Level == "error" {
				mark = "error"
			}
			fmt.Fprintf(&b, "  %s %s\n", mark, d.Message)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func formatMetricValue(m analyze.Metric) string {
	if m.Value == nil {
		// Not zero. Not "-". The metric could not be measured, and the terminal says so.
		return "not measured"
	}
	switch v := m.Value.(type) {
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}

		return fmt.Sprintf("%.2f", v)
	case bool:
		if v {
			return "yes"
		}

		return "no"
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func formatEvidence(m analyze.Metric) string {
	n := len(m.EvidenceRefs)
	if m.OmittedCount > 0 {
		return fmt.Sprintf("%d (+%d omitted)", n, m.OmittedCount)
	}
	if n == 0 && m.Value == nil {
		return "—"
	}

	return fmt.Sprintf("%d", n)
}

func classificationOf(m analyze.Metric) string {
	if m.Classification == nil {
		return ""
	}

	return m.Classification.Label
}
