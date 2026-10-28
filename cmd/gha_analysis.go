package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Vulnetix/vdb-sca-match/ghaudit"
	"github.com/Vulnetix/vdb-sca-match/sarif"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/analyze/forge"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/ghtasks"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// The gha analysis tasks: GitHub posture checks from the shared engine
// (vdb-sca-match ghaudit), the same rules the Software Factory evaluates on
// GitHub App events. Each task is a group of rules; audit runs every group.
//
// Files come from a local checkout when one is given (the default when the
// current directory has .github/), otherwise from the repository through the
// API. Settings, rulesets, environments and resolved action references come
// from the API when a GitHub token is available; without one, the rules that
// need them report "not evaluated" rather than passing, and the workflow
// rules still run.

type ghaTaskOptions struct {
	repo, ref, org, apiURL string
	format, output         string
	minSeverity, failOn    string
	offline, upload        bool
	rules                  []string
	maxActionRefs          int
	jsonOut                bool
}

var ghaTaskOpts ghaTaskOptions

type ghaTaskSpec struct {
	use, short, long string
	tasks            []ghaudit.Task
}

var ghaTaskSpecs = []ghaTaskSpec{
	{"workflows [path]", "Find injection, privilege and trust flaws in GitHub Actions workflows",
		`Analyse workflow and composite action files for the ways attackers abuse CI:
untrusted input expanded into scripts (followed through env, GITHUB_ENV, step
and job outputs and local composite actions), privileged triggers that run pull
request code, credential persistence into artifacts, artifact and cache
poisoning, excessive or undeclared token permissions, OIDC tokens outside a
protected environment, secrets exposed in bulk or sent to other hosts, unsound
conditions, spoofable bot checks and self-hosted runners reachable from forks.

With a GitHub token the repository's own settings rate each finding: a private
repository with forking disabled, a read-only default token, or an environment
with required reviewers lowers it; a public repository raises it.`,
		[]ghaudit.Task{ghaudit.TaskWorkflows}},
	{"actions [path]", "Check the actions and images workflows run",
		`Analyse every uses: reference: references not pinned to a commit SHA, SHA pins
whose version comment points elsewhere, commits that exist only in a fork of the
action (impostor commits), archived, renamed or deleted action repositories
(repo-jacking), action versions with a published advisory (looked up in
Vulnetix, the community tier when not logged in), retired runtimes,
typosquatted owners, actions outside the allowed-actions policy, unpinned
container images and remote scripts piped into a shell. Resolving references
needs a GitHub token.`,
		[]ghaudit.Task{ghaudit.TaskActions}},
	{"settings", "Check repository settings that protect the code and CI",
		`Read the repository's configuration through the GitHub API and check it:
default-branch protection merged from rulesets and classic protection (reviews,
stale approvals, code owners, force pushes, bypass actors, status checks,
signatures), Actions token defaults, PR approval by Actions, fork pull request
approval, allowed actions, secret scanning and push protection, Dependabot,
environment protection, deploy keys, webhooks, outside admins, policy files and
secret age. Needs a token with read access to the repository's administration
settings.`,
		[]ghaudit.Task{ghaudit.TaskSettings}},
	{"org", "Check organisation settings",
		`Read the organisation's configuration: two-factor enforcement, the members'
default repository permission, public repository creation, the Actions policy
and default token, organisation secrets visible to every repository, runner
groups open to public repositories, and webhooks. Needs an owner's token.`,
		[]ghaudit.Task{ghaudit.TaskOrg}},
	{"audit [path]", "Run every GitHub posture check: workflows, actions, settings and org",
		`Run workflows, actions, settings and (with --org, or for an organisation-owned
repository) org together, and report one result. With --upload the SARIF is
published to Vulnetix as an IAC snapshot, where it sits next to the findings the
Software Factory files from GitHub App events.`,
		ghaudit.AllTasks},
}

func newGHATaskCmd(spec ghaTaskSpec) *cobra.Command {
	name, _, _ := strings.Cut(spec.use, " ")
	c := &cobra.Command{
		Use:   spec.use,
		Short: spec.short,
		Long:  spec.long + "\n\nExamples:\n  vulnetix gha " + name + "\n  vulnetix gha " + name + " --repo acme/api --format sarif --output gh.sarif\n  vulnetix gha " + name + " --fail-on high",
		Args:  cobra.MaximumNArgs(1),
		// Credentials are only needed to publish; analysis runs without them.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			printBanner(cmd)
			initDisplayContext(cmd, display.ModeText)
			if ghaTaskOpts.upload {
				return resolveVDBCredentials(true)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			}
			return runGHATask(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), spec.tasks, path, ghaTaskOpts)
		},
	}
	f := c.Flags()
	f.StringVar(&ghaTaskOpts.repo, "repo", "", "Repository as owner/name (default: GITHUB_REPOSITORY, then the checkout's GitHub remote)")
	f.StringVar(&ghaTaskOpts.ref, "ref", "", "Branch, tag or commit to read files at when they come from the API (default: the default branch)")
	f.StringVar(&ghaTaskOpts.org, "org", "", "Organisation to check (default: the repository owner when it is an organisation, for org and audit)")
	f.StringVar(&ghaTaskOpts.apiURL, "github-api-url", "", "GitHub API base URL for GitHub Enterprise Server (default: GITHUB_API_URL or https://api.github.com)")
	f.StringVar(&ghaTaskOpts.format, "format", "table", "Output format: table, json or sarif")
	f.BoolVar(&ghaTaskOpts.jsonOut, "json", false, "Shorthand for --format json")
	f.StringVarP(&ghaTaskOpts.output, "output", "o", "", "Write the report to a file instead of stdout")
	f.StringVar(&ghaTaskOpts.minSeverity, "min-severity", "", "Drop findings below this severity: critical, high, medium, low")
	f.StringVar(&ghaTaskOpts.failOn, "fail-on", "", "Exit 1 when a finding is at or above this severity")
	f.BoolVar(&ghaTaskOpts.offline, "offline", false, "Do not call the GitHub API: analyse local files only")
	f.BoolVar(&ghaTaskOpts.upload, "upload", false, "Publish the SARIF to Vulnetix as a snapshot (needs Vulnetix credentials)")
	f.StringSliceVar(&ghaTaskOpts.rules, "rule", nil, "Only run these rule ids (repeatable)")
	f.IntVar(&ghaTaskOpts.maxActionRefs, "max-action-refs", 40, "Most distinct uses: references to resolve through the API")
	return c
}

// ghaTaskFilesRoot picks the local checkout to read, or "" to read through
// the API: an explicit path, else the current directory when it has .github/.
func ghaTaskFilesRoot(path string) string {
	if path != "" {
		return path
	}
	if st, err := os.Stat(".github"); err == nil && st.IsDir() {
		return "."
	}
	return ""
}

func ghaTaskRepo(opt ghaTaskOptions, root, host string) string {
	if opt.repo != "" {
		return opt.repo
	}
	if v := os.Getenv("GITHUB_REPOSITORY"); v != "" && (host == "github.com" || os.Getenv("GITHUB_SERVER_URL") != "") {
		return v
	}
	dir := root
	if dir == "" {
		dir = "."
	}
	if g := gitctx.Collect(dir); g != nil {
		for _, r := range g.RemoteURLs {
			if repo := ghtasks.RepoFromRemote(r, host); repo != "" {
				return repo
			}
		}
	}
	return ""
}

func runGHATask(ctx context.Context, stdout, stderr io.Writer, tasks []ghaudit.Task, path string, opt ghaTaskOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opt.jsonOut {
		opt.format = "json"
	}
	switch opt.format {
	case "table", "json", "sarif":
	default:
		return fmt.Errorf("--format must be table, json or sarif, got %q", opt.format)
	}
	minSev, failOn := ghaudit.ParseSeverity(opt.minSeverity), ghaudit.ParseSeverity(opt.failOn)
	if opt.minSeverity != "" && minSev == "" {
		return fmt.Errorf("--min-severity: unknown severity %q", opt.minSeverity)
	}
	if opt.failOn != "" && failOn == "" {
		return fmt.Errorf("--fail-on: unknown severity %q", opt.failOn)
	}
	apiURL := opt.apiURL
	if apiURL == "" {
		apiURL = os.Getenv("GITHUB_API_URL")
	}
	host := ghtasks.HostForAPI(apiURL)

	needsAPI := false
	for _, t := range tasks {
		if t == ghaudit.TaskSettings || t == ghaudit.TaskOrg {
			needsAPI = true
		}
	}
	root := ghaTaskFilesRoot(path)
	var files map[string][]byte
	if root != "" {
		var err error
		if files, err = ghtasks.LoadLocal(root); err != nil {
			return fmt.Errorf("read %s: %w", root, err)
		}
	}
	repo := ghaTaskRepo(opt, root, host)

	var notes []string
	var facts *ghaudit.Facts
	headSHA, ref := "", opt.ref
	if !opt.offline && (repo != "" || opt.org != "") {
		creds, err := forge.ResolveCredentials(ctx)
		switch {
		case err != nil && root == "":
			return fmt.Errorf("no local workflows and no GitHub token to read them with: run inside a checkout, or set GITHUB_TOKEN (or gh auth login)")
		case err != nil:
			notes = append(notes, "no GitHub token (GITHUB_TOKEN, GH_TOKEN or gh auth login): settings and action references were not read; rules that need them are reported as not evaluated")
		default:
			org := opt.org
			wantOrg := false
			for _, t := range tasks {
				if t == ghaudit.TaskOrg {
					wantOrg = true
				}
			}
			if wantOrg && org == "" && repo != "" {
				org, _, _ = strings.Cut(repo, "/") // collected only if it is an organisation; a user account 404s
			}
			if !wantOrg {
				org = ""
			}
			g := ghtasks.NewRESTGetter(apiURL, creds.Token)
			// Known-vulnerable action versions (VNX-GH-105) come from Vulnetix.
			var advisories *ghtasks.Advisories
			if ghaTasksInclude(tasks, ghaudit.TaskActions) {
				if lookup := ghaAdvisoryLookup(); lookup != nil {
					advisories = &ghtasks.Advisories{Lookup: lookup}
				} else {
					notes = append(notes, "no Vulnetix client: action versions were not checked for published advisories (VNX-GH-105)")
				}
			}
			copts := ghaudit.CollectOptions{Repo: repo, Org: org, Ref: opt.ref, Files: files, MaxActionRefs: opt.maxActionRefs}
			if advisories != nil {
				copts.Advisories = advisories.Func()
			}
			cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
			// Local files are evaluated as they are on disk; the API supplies the
			// settings and resolves their uses: references.
			col, cerr := ghaudit.Collect(cctx, g, copts)
			cancel()
			if advisories != nil && advisories.Failed {
				notes = append(notes, "some advisory lookups failed: VNX-GH-105 may have missed a known-vulnerable action version")
			}
			if cerr != nil {
				if errors.Is(cerr, ghtasks.ErrRateLimited) {
					return cerr
				}
				if root == "" {
					return cerr
				}
				notes = append(notes, "GitHub API: "+cerr.Error())
			}
			if col != nil {
				facts = col.Facts
				headSHA, ref = col.HeadSHA, col.Ref
				notes = append(notes, col.Notes...)
				if root == "" {
					files = col.Files
				}
			}
			notes = append(notes, fmt.Sprintf("%d GitHub API request(s) as %s", g.Calls, creds.Source))
		}
	} else if needsAPI && !opt.offline {
		notes = append(notes, "no repository found (pass --repo owner/name): settings rules were not evaluated")
	}
	if files == nil && !needsAPI {
		return fmt.Errorf("no workflow files found: run inside a checkout with .github/, pass a path, or pass --repo with a GitHub token")
	}

	rep := ghaudit.Evaluate(&ghaudit.Input{Repository: repo, Ref: ref, CommitSHA: headSHA, Files: files, Facts: facts,
		Tasks: tasks, RuleIDs: opt.rules, MinSeverity: minSev})
	notes = append(notes, rep.Notes...)
	sum := ghtasks.Summarise(rep, len(files))

	repoURI := ""
	if repo != "" {
		repoURI = "https://" + host + "/" + repo
	}
	log := rep.SARIF(ghaudit.SARIFOptions{ToolVersion: version, RepositoryURI: repoURI, Branch: ref, Revision: headSHA})
	log.AddExecutionNotifications(notes)

	out := stdout
	if opt.output != "" {
		fh, err := os.Create(opt.output)
		if err != nil {
			return err
		}
		defer fh.Close()
		out = fh
	}
	switch opt.format {
	case "sarif":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(log); err != nil {
			return err
		}
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"repository": repo, "ref": ref, "commit": headSHA, "summary": sum, "findings": rep.Findings,
			"coverage": rep.Coverage, "notes": notes, "errors": rep.Errors}); err != nil {
			return err
		}
	default:
		ghtasks.WriteTable(out, rep, sum, notes)
	}

	if opt.upload {
		if err := ghaTaskUpload(ctx, stderr, log, root); err != nil {
			return err
		}
	}
	if ghtasks.FailsAt(rep, failOn) {
		return fmt.Errorf("found %d finding(s) at or above %s", countAtLeast(rep, failOn), failOn)
	}
	return nil
}

func ghaTasksInclude(tasks []ghaudit.Task, want ghaudit.Task) bool {
	for _, t := range tasks {
		if t == want {
			return true
		}
	}
	return false
}

// ghaVersionRE is a tag that names a version; only those are looked up.
var ghaVersionRE = regexp.MustCompile(`^v?\d+\.\d+(\.\d+)?([-+][0-9A-Za-z.-]+)?$`)

// ghaAdvisoryLookup returns the advisory lookup for VNX-GH-105, or nil with no
// Vulnetix client. Without stored credentials the community tier answers.
// Replaceable in tests.
var ghaAdvisoryLookup = func() ghtasks.AdvisoryLookup {
	if vdbCreds == nil {
		_ = resolveVDBCredentials(false)
	}
	client := newCliClient()
	if client == nil {
		return nil
	}
	env := envForCliWithGit(nil)
	return func(ctx context.Context, action, ref string) ([]ghaudit.ActionAdvisory, bool) {
		if !ghaVersionRE.MatchString(ref) {
			return nil, true // a branch, a SHA or a bare major tag names no version
		}
		resp, err := client.CliGitHubAdvisories(ctx, env, []vdb.CliGitHubActionRef{{Action: action, Ref: ref}})
		if err != nil || resp == nil {
			return nil, false
		}
		var out []ghaudit.ActionAdvisory
		for _, a := range resp.Data.Advisories[action+"@"+ref] {
			sum := ""
			if a.Range != "" {
				sum = "affected range " + a.Range
			}
			out = append(out, ghaudit.ActionAdvisory{ID: a.ID, Summary: sum})
		}
		return out, !resp.Data.Incomplete
	}
}

func countAtLeast(rep *ghaudit.Report, sev ghaudit.Severity) int {
	n := 0
	for _, f := range rep.Findings {
		if f.Severity.AtLeast(sev) {
			n++
		}
	}
	return n
}

// ghaTaskUpload publishes the report to /v2/cli.github, chunked like a relayed
// report: chunk 0 creates the snapshot and later chunks append to it.
func ghaTaskUpload(ctx context.Context, stderr io.Writer, log *sarif.Log, root string) error {
	client := newCliClient()
	if client == nil {
		return fmt.Errorf("no Vulnetix client: run 'vulnetix auth login' or set VULNETIX_ORG_ID and VULNETIX_API_KEY")
	}
	var git *gitctx.GitContext
	if root != "" {
		git = gitctx.Collect(root)
	}
	env := envForCliWithGit(git)
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{ToolName: ghaudit.ToolName, ToolVersion: version, ToolVendor: "Vulnetix", ToolHash: commit}
	snapshot, url := "", ""
	chunks := chunkGHASARIF(log)
	for i, ch := range chunks {
		req := vdb.CliSARIFRequest{SARIF: ch.doc}
		if snapshot != "" {
			req.IngestionSnapshotUuid = snapshot
		} else if i > 0 {
			return fmt.Errorf("chunk 0 returned no snapshot to append to (check your Vulnetix credentials)")
		}
		resp, err := client.CliGitHub(ctx, env, req)
		if err != nil {
			if isCli404(err) {
				return fmt.Errorf("the Vulnetix API does not accept /v2/cli.github yet: %w", err)
			}
			return fmt.Errorf("upload chunk %d/%d: %w", i+1, len(chunks), err)
		}
		if i == 0 && resp != nil && resp.Data.IngestionSnapshot != nil {
			snapshot, url = resp.Data.IngestionSnapshot.Uuid, resp.Data.IngestionSnapshot.URL
		}
	}
	if snapshot == "" {
		fmt.Fprintln(stderr, notPersistedReason)
		return nil
	}
	fmt.Fprintf(stderr, "Published to Vulnetix: %s\n", firstNonEmptyStr(url, snapshot))
	return nil
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func init() {
	for _, spec := range ghaTaskSpecs {
		ghaCmd.AddCommand(newGHATaskCmd(spec))
	}
}
