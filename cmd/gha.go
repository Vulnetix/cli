package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/ghactx"
	"github.com/vulnetix/cli/v3/internal/github"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var (
	// GHA command flags.
	//
	// There is no --base-url here: both subcommands go through the shared
	// /v2/cli.* client, whose endpoint is set by VULNETIX_API_URL. A flag that
	// silently changed nothing was worse than no flag.
	ghaRunID         string
	ghaStatusAttempt int
	ghaUUID          string
	ghaOutputJSON    bool
	ghaFromDir       string
	ghaDryRun        bool
	ghaStrict        bool
	ghaNoGitHubAPI   bool
	ghaFailOnEmpty   bool
)

// ghaCmd represents the gha command for GitHub Actions artifact management
var ghaCmd = &cobra.Command{
	Use:   "gha",
	Short: "GitHub Actions artifact management",
	Long: `Manage GitHub Actions artifacts for Vulnetix.

This command allows you to upload workflow artifacts to Vulnetix and check their status.
It is designed to work within GitHub Actions workflows.`,
}

// ghaUploadCmd handles uploading artifacts from GitHub Actions
var ghaUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Publish third-party scanner reports from a workflow run to Vulnetix",
	Long: `Publish every scanner report produced by the current GitHub Actions workflow run.

This command:
1. Collects all artifacts from the current workflow run
2. Downloads and extracts each artifact
3. Classifies each file as SARIF, CycloneDX or SPDX, validates it, and reports
   what it found — including exactly why a broken report was rejected
4. Publishes each one to the Vulnetix endpoint for its scan category, attributed
   to the tool that actually produced it (gosec, grype, checkov, …)
5. Reports the ingestion snapshot for each published file

Exits non-zero if any file fails to publish.

Example:
  vulnetix gha upload --org-id <uuid>
  vulnetix gha upload --org-id <uuid> --json
  vulnetix gha upload --from-dir ./artifacts --dry-run --no-github-api`,
	// Credentials must resolve before anything is published. Without this the
	// package-level credentials stay nil, the client falls back to the shared
	// community credential, and the server refuses to persist anything under it —
	// a silent no-op that looks exactly like success.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		printBanner(cmd)
		initDisplayContext(cmd, display.ModeText)
		return resolveVDBCredentials(true)
	},
	RunE: runGHAUpload,
}

// ghaStatusCmd handles checking status of uploads
var ghaStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report what a workflow run published to Vulnetix",
	Long: `Report the scan results a ` + "`vulnetix gha upload`" + ` recorded.

One publish job fans out into a separate scanner run per third-party tool, so
this reports every tool from the workflow run, what category it was filed under,
and how many findings it contributed. Run it after ` + "`gha upload`" + ` to confirm what
actually landed rather than trusting a green check.

Inside a workflow it defaults to the current run, so no arguments are needed.

Examples:
  vulnetix gha status
  vulnetix gha status --run-id 30155614396
  vulnetix gha status --run-id 30155614396 --attempt 2 --json
  vulnetix gha status --uuid <ingestion-snapshot-uuid>`,
	// The report is org-scoped, so credentials must resolve first.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		printBanner(cmd)
		initDisplayContext(cmd, display.ModeText)
		return resolveVDBCredentials(true)
	},
	RunE: runGHAStatus,
}

func resolveOrgID() (string, error) {
	if orgID != "" {
		if _, err := uuid.Parse(orgID); err != nil {
			return "", fmt.Errorf("--org-id must be a valid UUID, got: %s", orgID)
		}
		return orgID, nil
	}

	// Try loading from stored credentials
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil {
		return "", fmt.Errorf("--org-id is required (no stored credentials found)")
	}
	if creds.OrgID == "" {
		return "", fmt.Errorf("--org-id is required (stored credentials have no org ID)")
	}
	return creds.OrgID, nil
}

func runGHAUpload(cmd *cobra.Command, args []string) error {
	dctx := display.FromCommand(cmd)
	t := dctx.Term
	ctx := cmd.Context()

	resolvedOrgID, err := resolveOrgID()
	if err != nil {
		return err
	}
	orgID = resolvedOrgID

	client := newCliClient()
	if client == nil {
		return fmt.Errorf("authentication required: run 'vulnetix auth login' first")
	}

	// Build the environment block once. The CI context is what gives a relayed
	// report its repo, branch, commit and workflow identity — a GitHub Actions
	// checkout is a detached HEAD, so the local git context alone would record
	// findings against "HEAD (detached)".
	env := envForCliWithGit(nil)

	var collector *github.ArtifactCollector
	var artifacts []github.Artifact

	if ghaFromDir == "" {
		if os.Getenv("GITHUB_ACTIONS") != "true" {
			dctx.Logger.Warn("Not running in GitHub Actions environment")
		}
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			return fmt.Errorf("GITHUB_TOKEN environment variable is required")
		}
		repository := os.Getenv("GITHUB_REPOSITORY")
		if repository == "" {
			return fmt.Errorf("GITHUB_REPOSITORY environment variable is required")
		}
		runID := os.Getenv("GITHUB_RUN_ID")
		if runID == "" {
			return fmt.Errorf("GITHUB_RUN_ID environment variable is required")
		}
		apiURL := os.Getenv("GITHUB_API_URL")
		if apiURL == "" {
			apiURL = "https://api.github.com"
		}
		collector = github.NewArtifactCollector(token, apiURL, repository, runID)
	}

	ciOpts := ghactx.Options{
		NoAPI: ghaNoGitHubAPI || collector == nil,
		Warn:  func(format string, args ...any) { dctx.Logger.Warnf(format, args...) },
	}
	if collector != nil {
		ciOpts.Lookup = ghactx.CollectorLookup{Collector: collector}
	}
	env.CI = ghactx.Collect(ctx, ciOpts)

	dctx.Logger.Info(display.Bold(t, "Publishing GitHub Actions scanner artifacts to Vulnetix"))
	kv := []display.KVPair{{Key: "Organization", Value: orgID}}
	if env.CI != nil {
		kv = append(kv,
			display.KVPair{Key: "Repository", Value: env.CI.Repository},
			display.KVPair{Key: "Run", Value: fmt.Sprintf("%d (attempt %d)", env.CI.RunID, env.CI.RunAttempt)},
			display.KVPair{Key: "Event", Value: env.CI.EventName},
		)
	}
	dctx.Logger.Info(display.KeyValue(t, kv))
	dctx.Logger.Info("")

	progress := dctx.Progress("GitHub Actions artifact publish", 3)

	// Gather the files to publish, either from the workflow run's artifacts or
	// from a local directory (--from-dir, which makes this whole path runnable
	// without a workflow).
	var sources []ghaArtifactFiles
	if collector != nil {
		progress.SetStage("Fetching workflow artifacts")
		artifacts, err = collector.ListArtifacts(ctx)
		if err != nil {
			progress.Fail("failed to fetch workflow artifacts")
			return fmt.Errorf("failed to list artifacts: %w", err)
		}
		if len(artifacts) == 0 {
			progress.Complete("no artifacts found")
			dctx.Logger.Warn("No artifacts found in this workflow run")
			if ghaFailOnEmpty {
				return fmt.Errorf("no artifacts found in workflow run (--fail-on-empty)")
			}
			return emitGHAJSON(nil, env)
		}
		dctx.Logger.Infof("Found %d artifact(s)", len(artifacts))
		for i, artifact := range artifacts {
			dctx.Logger.Infof("   %d. %s (%d bytes)", i+1, artifact.Name, artifact.SizeInBytes)
		}
		dctx.Logger.Info("")
		progress.Update(1, fmt.Sprintf("Found %d artifact(s)", len(artifacts)))

		sources, err = downloadArtifacts(ctx, collector, artifacts, progress)
		defer cleanupArtifacts(sources)
		if err != nil {
			progress.Fail("failed to download workflow artifacts")
			return err
		}
	} else {
		progress.SetStage("Reading local artifact directory")
		sources, err = localArtifactFiles(ghaFromDir)
		if err != nil {
			progress.Fail("failed to read artifact directory")
			return err
		}
		progress.Update(1, fmt.Sprintf("Found %d artifact(s) under %s", len(sources), ghaFromDir))
	}

	submitter := &ghaSubmitter{
		client: client,
		env:    env,
		ctx:    ctx,
		dryRun: ghaDryRun,
		strict: ghaStrict,
		logf:   func(format string, args ...any) { dctx.Logger.Infof(format, args...) },
		warnf:  func(format string, args ...any) { dctx.Logger.Warnf(format, args...) },
	}

	progress.Update(2, "Publishing")
	var results []ghaFileResult
	for _, src := range sources {
		for j, path := range src.files {
			progress.SetStage(fmt.Sprintf("%s: file %d/%d", src.name, j+1, len(src.files)))
			results = append(results, submitter.publishFile(src.name, path))
		}
	}

	var uploaded, failed, skipped int
	for _, r := range results {
		switch r.Status {
		case "error":
			failed++
		case "skipped":
			skipped++
		default:
			uploaded++
		}
	}
	if ghaStrict {
		failed += skipped
		skipped = 0
	}

	progress.Update(3, fmt.Sprintf("Published %d/%d file(s)", uploaded, len(results)))
	if failed > 0 {
		progress.Fail(fmt.Sprintf("%d file(s) failed to publish", failed))
	} else {
		progress.Complete("GitHub Actions publish complete")
	}

	for _, r := range results {
		if r.Status == "error" {
			dctx.Logger.Errorf("  %s/%s failed: %s", r.Name, r.File, r.Error)
		}
	}

	if err := emitGHAJSON(results, env); err != nil {
		return err
	}

	// A publish job whose every upload failed used to exit 0 and show a green
	// check. It now fails the build, which is the only way a broken pipeline
	// gets noticed.
	if failed > 0 {
		return fmt.Errorf("%d of %d artifact file(s) failed to publish to Vulnetix", failed, len(results))
	}
	if uploaded == 0 && ghaFailOnEmpty {
		return fmt.Errorf("no artifact file was published (--fail-on-empty)")
	}
	return nil
}

// ghaArtifactFiles is one artifact's extracted files, plus the temp directory to
// clean up afterwards.
type ghaArtifactFiles struct {
	name  string
	dir   string
	files []string
	// owned is false for --from-dir sources, which the caller must not delete.
	owned bool
}

// downloadArtifacts fetches and extracts every artifact. A download or read
// failure is fatal: publishing a partial subset while reporting success is how
// the previous implementation hid a fully broken pipeline.
func downloadArtifacts(ctx context.Context, collector *github.ArtifactCollector, artifacts []github.Artifact, progress *display.Progress) ([]ghaArtifactFiles, error) {
	out := make([]ghaArtifactFiles, 0, len(artifacts))
	for i, artifact := range artifacts {
		progress.SetStage(fmt.Sprintf("Downloading artifact %d/%d: %s", i+1, len(artifacts), artifact.Name))
		dir, err := collector.DownloadArtifact(ctx, artifact)
		if err != nil {
			return out, fmt.Errorf("download artifact %q: %w", artifact.Name, err)
		}
		files, err := findFiles(dir)
		if err != nil {
			return append(out, ghaArtifactFiles{name: artifact.Name, dir: dir, owned: true}),
				fmt.Errorf("read artifact %q: %w", artifact.Name, err)
		}
		out = append(out, ghaArtifactFiles{name: artifact.Name, dir: dir, files: files, owned: true})
	}
	return out, nil
}

func cleanupArtifacts(sources []ghaArtifactFiles) {
	for _, s := range sources {
		if s.owned && s.dir != "" {
			os.RemoveAll(s.dir)
		}
	}
}

// localArtifactFiles walks a directory laid out like downloaded artifacts: one
// subdirectory per artifact name. A flat directory is treated as a single
// artifact named after it.
func localArtifactFiles(root string) ([]ghaArtifactFiles, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", root, err)
	}

	var out []ghaArtifactFiles
	var loose []string
	for _, e := range entries {
		full := filepath.Join(root, e.Name())
		if !e.IsDir() {
			loose = append(loose, full)
			continue
		}
		files, err := findFiles(full)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", full, err)
		}
		if len(files) > 0 {
			out = append(out, ghaArtifactFiles{name: e.Name(), dir: full, files: files})
		}
	}
	if len(loose) > 0 {
		out = append(out, ghaArtifactFiles{name: filepath.Base(root), dir: root, files: loose})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no files found under %s", root)
	}
	return out, nil
}

// emitGHAJSON prints the machine-readable summary when --json is set. The
// original keys (artifacts, total, success) are preserved so existing consumers
// keep parsing; everything else is additive.
func emitGHAJSON(results []ghaFileResult, env vdb.CliEnv) error {
	if !ghaOutputJSON {
		return nil
	}
	uploaded, failed, skipped := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case "error":
			failed++
		case "skipped":
			skipped++
		default:
			uploaded++
		}
	}
	if results == nil {
		results = []ghaFileResult{}
	}

	output := map[string]any{
		"artifacts": results,
		"total":     len(results),
		"success":   uploaded,
		"failed":    failed,
		"skipped":   skipped,
	}
	if env.CI != nil {
		output["ci"] = map[string]any{
			"repository": env.CI.Repository,
			"runId":      env.CI.RunID,
			"runAttempt": env.CI.RunAttempt,
			"event":      env.CI.EventName,
			"refName":    env.CI.RefName,
			"sha":        env.CI.SHA,
		}
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

// findFiles recursively finds all files in a directory
func findFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func runGHAStatus(cmd *cobra.Command, args []string) error {
	dctx := display.FromCommand(cmd)
	t := dctx.Term
	ctx := cmd.Context()

	resolvedOrgID, err := resolveOrgID()
	if err != nil {
		return err
	}
	orgID = resolvedOrgID

	req := vdb.CliGHAStatusRequest{RunAttempt: ghaStatusAttempt}
	switch {
	case ghaUUID != "":
		req.SnapshotUuid = ghaUUID
		req.RunAttempt = 0
	case ghaRunID != "":
		id, parseErr := strconv.ParseInt(ghaRunID, 10, 64)
		if parseErr != nil {
			return fmt.Errorf("--run-id must be a workflow run id, got %q", ghaRunID)
		}
		req.RunID = id
	default:
		// Inside the same workflow this defaults to the current run, so
		// `gha status` immediately after `gha upload` needs no arguments.
		id, parseErr := strconv.ParseInt(os.Getenv("GITHUB_RUN_ID"), 10, 64)
		if parseErr != nil || id <= 0 {
			return fmt.Errorf("--run-id is required outside a GitHub Actions run (or pass --uuid for one snapshot)")
		}
		req.RunID = id
		if req.RunAttempt == 0 {
			if attempt, aErr := strconv.Atoi(os.Getenv("GITHUB_RUN_ATTEMPT")); aErr == nil {
				req.RunAttempt = attempt
			}
		}
	}

	client := newCliClient()
	if client == nil {
		return fmt.Errorf("authentication required: run 'vulnetix auth login' first")
	}

	progress := dctx.Progress("GitHub Actions publish status", 1)
	if req.SnapshotUuid != "" {
		progress.SetStage("Looking up snapshot " + req.SnapshotUuid)
	} else {
		progress.SetStage(fmt.Sprintf("Looking up workflow run %d", req.RunID))
	}

	resp, err := client.CliGHAStatus(ctx, envForCliWithGit(nil), req)
	if err != nil {
		progress.Fail("status lookup failed")
		if isCli404(err) {
			return fmt.Errorf("this Vulnetix API does not support gha status (upgrade the backend): %w", err)
		}
		return fmt.Errorf("failed to get status: %w", err)
	}
	progress.Complete("status lookup complete")

	status := resp.Data
	if ghaOutputJSON {
		jsonData, mErr := json.MarshalIndent(status, "", "  ")
		if mErr != nil {
			return fmt.Errorf("failed to marshal JSON: %w", mErr)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	printGHAStatus(dctx, t, status)
	return nil
}

// printGHAStatus renders the per-tool report a CI operator reads after a publish.
func printGHAStatus(dctx *display.Context, t *display.Terminal, status vdb.CliGHAStatusResponse) {
	dctx.Logger.Info("")
	if len(status.Runs) == 0 {
		if status.Message != "" {
			dctx.Logger.Warn(status.Message)
		} else {
			dctx.Logger.Warn("No scan results recorded for this run")
		}
		return
	}

	header := fmt.Sprintf("%d scan result(s) from %d tool(s), %d finding(s) ingested",
		len(status.Runs), status.Tools, status.Total)
	dctx.Logger.Info(display.Bold(t, header))
	dctx.Logger.Info("")

	for _, run := range status.Runs {
		title := run.ToolName
		if run.ToolVersion != "" {
			title += " " + run.ToolVersion
		}
		if run.Vendor != "" && !strings.EqualFold(run.Vendor, run.ToolName) {
			title += " (" + run.Vendor + ")"
		}
		dctx.Logger.Infof("%s  [%s]", display.Bold(t, title), run.Category)
		dctx.Logger.Infof("   findings: %d ingested (crit %d, high %d, med %d, low %d, info %d)",
			run.IngestedTotal, run.Critical, run.High, run.Medium, run.Low, run.Informational)
		if run.RepoName != "" {
			dctx.Logger.Infof("   repo:     %s", run.RepoName)
		}
		if run.RunAttempt > 1 {
			dctx.Logger.Infof("   attempt:  %d", run.RunAttempt)
		}
		if run.SnapshotURL != "" {
			dctx.Logger.Infof("   snapshot: %s", run.SnapshotURL)
		} else if run.SnapshotUuid != "" {
			dctx.Logger.Infof("   snapshot: %s", run.SnapshotUuid)
		}
		dctx.Logger.Info("")
	}
}

func init() {
	// Add upload subcommand
	ghaUploadCmd.Flags().BoolVar(&ghaOutputJSON, "json", false, "Output results as JSON")
	ghaUploadCmd.Flags().StringVar(&ghaFromDir, "from-dir", "", "Publish files from a local directory instead of the workflow run's artifacts")
	ghaUploadCmd.Flags().BoolVar(&ghaDryRun, "dry-run", false, "Classify and validate every file without publishing anything")
	ghaUploadCmd.Flags().BoolVar(&ghaStrict, "strict", false, "Treat skipped files (unrecognised formats) as failures")
	ghaUploadCmd.Flags().BoolVar(&ghaNoGitHubAPI, "no-github-api", false, "Do not call the GitHub REST API to enrich the CI context")
	ghaUploadCmd.Flags().BoolVar(&ghaFailOnEmpty, "fail-on-empty", false, "Fail when the run produced no publishable artifact")
	_ = ghaUploadCmd.Flags().MarkHidden("from-dir")

	// Add status subcommand
	ghaStatusCmd.Flags().StringVar(&ghaRunID, "run-id", "", "Workflow run id to report on (defaults to GITHUB_RUN_ID)")
	ghaStatusCmd.Flags().IntVar(&ghaStatusAttempt, "attempt", 0, "Limit to one run attempt (defaults to GITHUB_RUN_ATTEMPT)")
	ghaStatusCmd.Flags().StringVar(&ghaUUID, "uuid", "", "Report on a single ingestion snapshot instead of a whole run")
	ghaStatusCmd.Flags().BoolVar(&ghaOutputJSON, "json", false, "Output results as JSON")

	// Add subcommands to gha command
	ghaCmd.AddCommand(ghaUploadCmd, ghaStatusCmd)

	// Add gha command to root
	rootCmd.AddCommand(ghaCmd)
}
