package cmd

// `vulnetix gha publish <target>` publishes into GitHub in GitHub's own
// formats. It is independent of `gha upload`, which sends to Vulnetix: a run
// that is not signed in to Vulnetix (community mode) still publishes to
// GitHub, and a failure on one side only warns on the other.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/github"
	"github.com/vulnetix/cli/v3/internal/pipeline"
	"github.com/vulnetix/cli/v3/internal/sast"
)

var ghaPublishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish results into GitHub: code scanning, dependency graph, advisories, release assets",
	Long: `Publish this CLI's results into GitHub in GitHub's native formats.

  code-scanning     SARIF to GitHub code scanning, one category per scanner
                    (vulnetix/sast/, vulnetix/sca/, ...)

The token is GITHUB_TOKEN, then GH_TOKEN, then 'gh auth token'. GITHUB_API_URL
selects a GitHub Enterprise Server. Publishing to GitHub needs no Vulnetix
credentials, and sending to Vulnetix (gha upload) is unaffected by it.`,
}

// The publish targets a scan's --github-publish accepts.
const (
	publishCodeScanning   = "code-scanning"
	publishDependencyList = "dependency-graph"
)

var githubPublishTargets = []string{publishCodeScanning}

// publishTargetFlags are the flags every publish subcommand shares.
type publishTargetFlags struct {
	repo, sha, ref string
}

func (f *publishTargetFlags) register(c *cobra.Command) {
	c.Flags().StringVar(&f.repo, "repo", "", "Repository owner/name (default: GITHUB_REPOSITORY, then the git remote)")
	c.Flags().StringVar(&f.sha, "sha", "", "Commit SHA (default: GITHUB_SHA, then HEAD)")
	c.Flags().StringVar(&f.ref, "ref", "", "Git ref, e.g. refs/heads/main (default: GITHUB_REF, then the current branch)")
}

var (
	csTarget   publishTargetFlags
	csPath     string
	csSARIF    []string
	csOutDir   string
	csWait     time.Duration
	csCheckout string
)

var ghaPublishCodeScanningCmd = &cobra.Command{
	Use:   "code-scanning",
	Short: "Upload SARIF to GitHub code scanning",
	Long: `Upload SARIF to GitHub code scanning (POST /repos/{owner}/{repo}/code-scanning/sarifs).

Each file is split into one upload per scanner kind, with the category
vulnetix/<kind>/, so a secrets upload never closes a SAST alert. Results get
GitHub's line-hash fingerprint where they lack one, and each run keeps its
25,000 most severe results. The files actually uploaded are written to
--out-dir (default .vulnetix/code-scanning/).

Needs permissions: security-events: write (and actions: read on a private
repository).`,
	Example: `  vulnetix gha publish code-scanning
  vulnetix gha publish code-scanning --sarif .vulnetix/sast.sarif --sarif .vulnetix/sca.sarif`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		files := csSARIF
		if len(files) == 0 {
			files = defaultSARIFFiles(csPath)
		}
		if len(files) == 0 {
			return fmt.Errorf("no SARIF files in %s; run a scan first or pass --sarif", filepath.Join(csPath, ".vulnetix"))
		}
		var logs []*sast.SARIFLog
		for _, f := range files {
			l, err := sast.LoadExistingSARIF(f)
			if err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			if l != nil {
				logs = append(logs, l)
			}
		}
		return runCodeScanningPublish(cmd.Context(), codeScanningPublishOptions{
			Root: csPath, Logs: logs, OutDir: csOutDir, Wait: csWait,
			Repo: csTarget.repo, SHA: csTarget.sha, Ref: csTarget.ref, CheckoutURI: csCheckout,
		}, os.Stderr)
	},
}

// defaultSARIFFiles are the SARIF files a scan writes under root/.vulnetix.
func defaultSARIFFiles(root string) []string {
	matches, _ := filepath.Glob(filepath.Join(root, ".vulnetix", "*.sarif"))
	sort.Strings(matches)
	return matches
}

type codeScanningPublishOptions struct {
	Root string
	Logs []*sast.SARIFLog
	// EnsureKinds are kinds that ran: each gets an upload even with no
	// results, which is what closes the alerts a fix resolved.
	EnsureKinds []string
	OutDir      string
	Wait        time.Duration
	Repo, SHA   string
	Ref         string
	CheckoutURI string
	// Client overrides the GitHub client (tests).
	Client *github.Client
}

// codeScanningLogs merges every log, splits it per kind and adds an empty run
// for each ensured kind that has none.
func codeScanningLogs(logs []*sast.SARIFLog, ensure []string) map[string]*sast.SARIFLog {
	all := &sast.SARIFLog{Schema: sarifSchemaURL, Version: "2.1.0"}
	for _, l := range logs {
		if l != nil {
			all.Runs = append(all.Runs, l.Runs...)
		}
	}
	byKind := sast.SplitByKind(all)
	if len(all.Runs) == 0 {
		byKind = map[string]*sast.SARIFLog{}
	}
	for _, k := range ensure {
		k = sast.CategoryKind(k)
		if _, ok := byKind[k]; ok {
			continue
		}
		empty := sast.BuildSARIF(nil, nil, version)
		empty.Runs[0].AutomationDetails = &sast.SARIFAutomationDetails{ID: sast.AutomationID(k)}
		byKind[k] = empty
	}
	return byKind
}

const sarifSchemaURL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

// runCodeScanningPublish uploads one SARIF per kind. It returns an error when
// any upload failed; callers inside a scan turn that into a warning.
func runCodeScanningPublish(ctx context.Context, o codeScanningPublishOptions, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if o.Root == "" {
		o.Root = "."
	}
	if o.OutDir == "" {
		o.OutDir = filepath.Join(o.Root, ".vulnetix", "code-scanning")
	}
	byKind := codeScanningLogs(o.Logs, o.EnsureKinds)
	if len(byKind) == 0 {
		fmt.Fprintln(w, "  code scanning: nothing to publish")
		return nil
	}
	target, err := github.ResolveTarget(o.Root, o.Repo, o.SHA, o.Ref)
	if err != nil {
		return err
	}
	client := o.Client
	if client == nil {
		tok, _, terr := github.ResolveToken()
		if terr != nil {
			return terr
		}
		client = github.NewClient(tok)
	}
	if err := os.MkdirAll(o.OutDir, 0o755); err != nil {
		return err
	}

	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var failed []string
	for _, k := range kinds {
		l := byKind[k]
		if dropped := sast.PrepareForGitHub(l, o.Root); dropped > 0 {
			fmt.Fprintf(w, "  code scanning %s: kept the %d most severe results, dropped %d (GitHub's per-run limit)\n", k, sast.MaxGitHubResultsPerRun, dropped)
		}
		path := filepath.Join(o.OutDir, k+".sarif")
		if err := sast.WriteSARIF(l, path); err != nil {
			fmt.Fprintf(w, "  warning: could not write %s: %v\n", path, err)
		} else {
			recordArtifact(path, "sarif")
		}
		data, err := json.Marshal(l)
		if err != nil {
			return err
		}
		n := 0
		for _, r := range l.Runs {
			n += len(r.Results)
		}
		up, err := client.UploadSARIF(ctx, target, data, o.CheckoutURI)
		if err != nil {
			failed = append(failed, k)
			fmt.Fprintf(w, "  code scanning %s: upload failed: %v%s\n", k, err, permissionHint(err, "security-events: write"))
			continue
		}
		status := "uploaded"
		if o.Wait > 0 {
			st, werr := client.WaitSARIF(ctx, target.Repo, up.ID, o.Wait, 0)
			switch {
			case werr != nil:
				failed = append(failed, k)
				fmt.Fprintf(w, "  code scanning %s: %v\n", k, werr)
				continue
			case st != nil && st.ProcessingStatus != "":
				status = st.ProcessingStatus
			}
		}
		fmt.Fprintf(w, "  code scanning %s: %d result(s) %s (vulnetix/%s/, %s)\n", k, n, status, k, target.Ref)
	}
	if len(failed) > 0 {
		return fmt.Errorf("code scanning upload failed for %s", strings.Join(failed, ", "))
	}
	return nil
}

// permissionHint names the permission a 401/403/404 usually means is missing.
func permissionHint(err error, perm string) string {
	if github.IsPermission(err) {
		return fmt.Sprintf(" (the token needs %s; on a pull request from a fork it is read-only)", perm)
	}
	return ""
}

// recordArtifact notes a written file in the artifact manifest, when one is
// in use. Replaced by the manifest package's writer.
var recordArtifact = func(path, kind string) {}

// parseGitHubPublish validates --github-publish values.
func parseGitHubPublish(values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(strings.ToLower(p))
			if p == "" {
				continue
			}
			ok := false
			for _, t := range githubPublishTargets {
				if p == t {
					ok = true
				}
			}
			if !ok {
				return nil, fmt.Errorf("--github-publish: unknown target %q (want %s)", p, strings.Join(githubPublishTargets, ", "))
			}
			out = append(out, p)
		}
	}
	return out, nil
}

func hasPublishTarget(targets []string, t string) bool {
	for _, x := range targets {
		if x == t {
			return true
		}
	}
	return false
}

func init() {
	csTarget.register(ghaPublishCodeScanningCmd)
	ghaPublishCodeScanningCmd.Flags().StringVar(&csPath, "path", ".", "Repository root the SARIF locations are relative to")
	ghaPublishCodeScanningCmd.Flags().StringArrayVar(&csSARIF, "sarif", nil, "SARIF file to upload (repeatable; default: every .vulnetix/*.sarif under --path)")
	ghaPublishCodeScanningCmd.Flags().StringVar(&csOutDir, "out-dir", "", "Where to write the per-kind SARIF that is uploaded (default: <path>/.vulnetix/code-scanning)")
	ghaPublishCodeScanningCmd.Flags().DurationVar(&csWait, "wait", 2*time.Minute, "How long to wait for GitHub to process each upload (0 to not wait)")
	ghaPublishCodeScanningCmd.Flags().StringVar(&csCheckout, "checkout-uri", "", "URI of the checkout the SARIF paths are relative to, when not the repository root")
	ghaPublishCmd.AddCommand(ghaPublishCodeScanningCmd)
	ghaCmd.AddCommand(ghaPublishCmd)
}

// githubPublishKinds are the code scanning categories a scan covered: each
// gets an upload, empty when clean, so fixed alerts close.
func githubPublishKinds(noSAST, noSecrets, noIAC, noContainers, noSCA bool) []string {
	var k []string
	add := func(off bool, name string) {
		if !off {
			k = append(k, name)
		}
	}
	add(noSAST, "sast")
	add(noSecrets, "secrets")
	add(noIAC, "iac")
	add(noContainers, "containers")
	add(noSCA, "sca")
	return k
}

// publishScanToGitHub runs the --github-publish targets at the end of a scan.
// Every failure is a warning: the scan's own result and its Vulnetix upload
// stand whatever GitHub says.
func publishScanToGitHub(ctx context.Context, opts pipeline.Options, root string, sastReport *sast.SASTReport, kinds []string, w io.Writer) {
	if hasPublishTarget(opts.GitHubPublish, publishCodeScanning) {
		var logs []*sast.SARIFLog
		if sastReport != nil {
			l := sast.BuildSARIF(sastReport.Findings, sastReport.Rules, version)
			l.AddExecutionNotifications(sastReport.Degradations)
			logs = append(logs, l)
		}
		if l, err := sast.LoadExistingSARIF(filepath.Join(root, ".vulnetix", "sca.sarif")); err == nil && l != nil && hasKind(kinds, "sca") {
			logs = append(logs, l)
		}
		if err := runCodeScanningPublish(ctx, codeScanningPublishOptions{
			Root: root, Logs: logs, EnsureKinds: kinds, Wait: 2 * time.Minute,
		}, w); err != nil {
			fmt.Fprintf(w, "  warning: GitHub code scanning: %v\n", err)
		}
	}
}

func hasKind(kinds []string, k string) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}
