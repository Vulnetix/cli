package analyze

// The orchestrator: run the collectors, assemble the graph, seal the report.
//
// The graph is assembled last, from what the collectors already found, because a graph built
// separately from the metrics would be a second source of truth that could disagree with the
// first. The nodes here ARE the files and dependencies the metrics counted.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"

	"github.com/vulnetix/cli/v3/internal/analyze/forge"
	"github.com/vulnetix/cli/v3/internal/sast"
)

type Options struct {
	Path string

	// WindowDays bounds the history walk. Everything derived from history is relative to it,
	// which is why the window is stamped on the report and on every metric that used it.
	WindowDays int
	MaxCommits int

	ComplexityThreshold int

	NoGit   bool
	NoFiles bool
	NoDeps  bool
	NoTrust bool
	NoForge bool

	// Silent suppresses the startup authentication line. The check still runs.
	Silent bool

	// Enrich fetches registry metadata for a batch of PURLs, so dependency staleness can be
	// computed. Nil when the user is not authenticated to the Vulnetix API — in which case the
	// staleness metrics are Unmeasured, not zero.
	Enrich EnrichFunc

	// Progress receives stage and step updates. Nil is valid and reports nothing — a long walk
	// with no output is indistinguishable from a hang, but only a terminal needs telling.
	Progress Reporter
}

func DefaultOptions() Options {
	return Options{
		Path:       ".",
		WindowDays: 365,
		// A cap, and one that is declared in the report when it is hit. Walking a million commits
		// to compute a bus factor is not worth the wall time, but pretending we walked them all is
		// not acceptable either.
		MaxCommits:          20000,
		ComplexityThreshold: 15,
	}
}

// Preflight resolves the repository and verifies forge access, before any scanning begins.
//
// It runs first and it can fail the command. A five-minute analysis that ends in a report
// where a third of the metrics are null because a token was missing is a waste of the user's
// time — and a report full of nulls is the kind of thing people stop reading, which then
// costs them the metrics that *were* measured.
type Preflight struct {
	Target Target
	Forge  *forge.Client
	Repo   forge.Repo

	// ForgeStatus explains what happened, and is printed unless silenced. Exactly one of
	// these three things is true, and the user is told which.
	ForgeStatus string
}

// Check performs the preflight. A non-nil error means the command should stop.
func Check(ctx context.Context, opts Options) (*Preflight, error) {
	root, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	p := &Preflight{Target: Target{RootPath: root}}

	repo, repoErr := git.PlainOpenWithOptions(root, &git.PlainOpenOptions{DetectDotGit: true})
	if repoErr == nil {
		fillTargetFromGit(&p.Target, repo, root)
	} else {
		// Without a remote there is no stable identity to join an org graph on. The scan still
		// runs — the metrics are all local — but the cross-repo keys will not match anything.
		p.Target.RepoID = "local~~" + filepath.Base(root)
	}

	host, owner, name := "", "", ""
	if p.Target.RemoteURL != "" {
		host, owner, name = parseRemote(p.Target.RemoteURL)
	}

	switch {
	case opts.NoForge:
		p.ForgeStatus = "GitHub: skipped (--no-forge). Pull-request, review and issue metrics will be reported as not measured."

		return p, nil

	case !forge.IsGitHubHost(host):
		// A GitLab repository must not fail for want of a GitHub token. Refusing to analyze a
		// repo we were never going to call GitHub about would be a bug wearing a security hat.
		p.ForgeStatus = fmt.Sprintf(
			"GitHub: skipped (%s is not a GitHub host). Pull-request, review and issue metrics will be reported as not measured.",
			orDefault(host, "no remote"))

		return p, nil
	}

	creds, err := forge.ResolveCredentials(ctx)
	if err != nil {
		return nil, err
	}

	forgeRepo := forge.Repo{Owner: owner, Name: name, DefaultBranch: p.Target.DefaultBranch}

	// The check proves the token is valid AND that it can see this repository. Those are
	// different questions: a fine-grained token can be perfectly valid for the user and still be
	// unable to read a private repo it was never granted — and GitHub reports that as a 404, so
	// the failure looks like a typo rather than a permission.
	result, err := forge.Check(ctx, creds, host, forgeRepo)
	if err != nil {
		return nil, err
	}

	client, err := forge.NewClient(creds, host)
	if err != nil {
		return nil, err
	}

	p.Forge = client
	p.Repo = forgeRepo
	p.ForgeStatus = result.String()

	return p, nil
}

// Run produces the report. Every collector that runs, is skipped, or fails is recorded on the
// report — so a consumer can always tell a metric that is missing from a metric that is zero.
func Run(tool Tool, opts Options, pre *Preflight) (*Report, []byte, error) {
	started := time.Now()
	now := started

	if pre == nil {
		var err error
		pre, err = Check(context.Background(), opts)
		if err != nil {
			return nil, nil, err
		}
	}
	if pre.ForgeStatus != "" && !opts.Silent {
		fmt.Fprintln(os.Stderr, pre.ForgeStatus)
	}

	root := pre.Target.RootPath
	target := pre.Target

	repo, repoErr := git.PlainOpenWithOptions(root, &git.PlainOpenOptions{DetectDotGit: true})

	b := NewBuilder(tool, target, started)

	// Every collector reports through this. A nil Reporter makes each call a no-op, so nothing
	// below needs to know whether a terminal is attached.
	pr := reporter{opts.Progress}

	var err error

	var gstats *gitStats
	if opts.NoGit || repoErr != nil {
		reason := "disabled with --no-git"
		if repoErr != nil {
			reason = "not a git repository: " + repoErr.Error()
		}
		b.Collected(Collector{Name: "git", Status: "skipped", Reason: reason})
		b.Diagnose(Diagnostic{Level: "warning", Collector: "git",
			Message: "History was not read, so every activity, contributor and ownership metric is absent from this report rather than zero."})
		pr.Step(stepGit, "Skipped history")
	} else {
		t := time.Now()
		pr.Stage("Walking history")
		gstats, err = collectGit(b, repo, opts, now, pr)
		if err != nil {
			b.Collected(Collector{Name: "git", Status: "failed", Reason: err.Error(),
				DurationSeconds: time.Since(t).Seconds()})
			b.Diagnose(Diagnostic{Level: "error", Collector: "git", Message: err.Error()})
			pr.Step(stepGit, "History failed")
		} else {
			b.SetWindow(&gstats.window)
			b.Collected(Collector{Name: "git", Status: "completed",
				DurationSeconds: time.Since(t).Seconds()})
			pr.Step(stepGit, "Read "+plural(gstats.walked, "commit", "commits")+
				" from "+plural(len(gstats.contributors), "contributor", "contributors"))
		}
	}

	var fstats *fileStats
	if opts.NoFiles {
		b.Collected(Collector{Name: "files", Status: "skipped", Reason: "disabled with --no-files"})
		pr.Step(stepFiles, "Skipped files")
	} else {
		t := time.Now()
		pr.Stage("Reading files")
		fstats, err = collectFiles(b, root, gstats, opts, now, pr)
		if err != nil {
			b.Collected(Collector{Name: "files", Status: "failed", Reason: err.Error(),
				DurationSeconds: time.Since(t).Seconds()})
			pr.Step(stepFiles, "Files failed")
		} else {
			b.Collected(Collector{Name: "files", Status: "completed",
				DurationSeconds: time.Since(t).Seconds()})
			pr.Step(stepFiles, "Measured "+plural(len(fstats.files), "source file", "source files"))
		}
	}

	var dstats *depStats
	if opts.NoDeps {
		b.Collected(Collector{Name: "dependencies", Status: "skipped", Reason: "disabled with --no-deps"})
		pr.Step(stepDeps, "Skipped dependencies")
	} else {
		t := time.Now()
		pr.Stage("Reading manifests")
		dstats, err = collectDeps(b, root, opts)
		if err != nil {
			b.Collected(Collector{Name: "dependencies", Status: "failed", Reason: err.Error(),
				DurationSeconds: time.Since(t).Seconds()})
			pr.Step(stepDeps, "Dependencies failed")
		} else {
			b.Collected(Collector{Name: "dependencies", Status: "completed",
				DurationSeconds: time.Since(t).Seconds()})
			pr.Step(stepDeps, "Found "+plural(len(dstats.deps), "dependency", "dependencies"))
		}
	}

	// Dependency staleness. Without credentials this is Unmeasured, never zero — "nothing is
	// stale" is a claim, and an unauthenticated run has not earned it.
	if dstats != nil {
		t := time.Now()
		if opts.Enrich != nil {
			pr.Stage("Checking " + plural(len(dstats.deps), "dependency", "dependencies") +
				" against the registry")
		}
		enrichDependencies(b, dstats, opts.Enrich, now)
		status := "completed"
		reason := ""
		msg := "Checked dependency staleness"
		if opts.Enrich == nil {
			status = "skipped"
			reason = "not authenticated; registry metadata was not fetched"
			msg = "Skipped staleness (not authenticated)"
		}
		b.Collected(Collector{Name: "dependency-enrichment", Status: status, Reason: reason,
			DurationSeconds: time.Since(t).Seconds()})
		pr.Step(stepEnrich, msg)
	} else {
		pr.Step(stepEnrich, "Skipped staleness")
	}

	// The policy checks and the history-secret passes share one SARIF log. Two logs would be two
	// findings surfaces for one scan.
	if opts.NoTrust {
		b.Collected(Collector{Name: "trust", Status: "skipped", Reason: "disabled with --no-trust"})
		pr.Step(stepTrust, "Skipped policy checks")
	} else {
		t := time.Now()
		pr.Stage("Checking open-source policy")
		tr := collectTrust(b, root)

		findings, rules := tr.findings, tr.rules
		if repoErr == nil && !opts.NoGit {
			pr.Stage("Searching history for secrets")
			findings, rules = collectSecrets(b, repo, gstats, findings, rules, pr)
		}
		b.SetSARIF(sast.BuildSARIF(findings, rules, "analyze"))

		b.Collected(Collector{Name: "trust", Status: "completed",
			DurationSeconds: time.Since(t).Seconds()})
		pr.Step(stepTrust, "Checked policy and history for secrets")
	}

	// Change coupling and the complexity trend both read history, and both declare what they
	// dropped when they hit a cap.
	var cpstats *couplingStats
	var tstats *trendStats
	if !opts.NoGit && repoErr == nil {
		t := time.Now()
		pr.Stage("Correlating co-changing files")
		cpstats = collectCoupling(b, gstats, fstats)
		b.Collected(Collector{Name: "coupling", Status: "completed",
			DurationSeconds: time.Since(t).Seconds()})
		pr.Step(stepCoupling, "Found "+plural(len(cpstats.edges), "coupled pair", "coupled pairs"))

		t = time.Now()
		pr.Stage("Tracking complexity over time")
		tstats = collectTrend(b, repo, fstats, gstats, opts, pr)
		b.Collected(Collector{Name: "trend", Status: "completed",
			DurationSeconds: time.Since(t).Seconds()})
		pr.Step(stepTrend, "Tracked complexity across "+
			plural(len(tstats.byPath), "file", "files"))
	}

	// The structural code graph and the cross-repo contract edges. Both read the files the
	// file collector already found, so they cost a second pass over the source and no second
	// walk of the tree.
	var sstats *symbolStats
	var cstats *contractStats
	if !opts.NoFiles && fstats != nil {
		// Go has no relative imports — everything is a module path — so resolving an internal Go
		// import needs to know what this module is called.
		modulePath := goModulePath(filepath.Join(root, "go.mod"))

		t := time.Now()
		pr.Stage("Extracting symbols")
		sstats = collectSymbols(b, root, fstats, modulePath, opts, pr)
		b.Collected(Collector{Name: "symbols", Status: "completed",
			DurationSeconds: time.Since(t).Seconds()})
		pr.Step(stepSymbols, "Extracted "+plural(len(sstats.nodes), "symbol", "symbols"))

		t = time.Now()
		pr.Stage("Finding cross-repo join keys")
		cstats = collectContracts(b, root, fstats, dstats, target)
		b.Collected(Collector{Name: "contracts", Status: "completed",
			DurationSeconds: time.Since(t).Seconds()})
		pr.Step(stepContracts, "Published "+plural(len(cstats.edges), "join key", "join keys"))
	} else {
		b.Collected(Collector{Name: "symbols", Status: "skipped", Reason: "the file pass did not run"})
		b.Collected(Collector{Name: "contracts", Status: "skipped", Reason: "the file pass did not run"})
		pr.Step(stepSymbols, "Skipped symbols")
		pr.Step(stepContracts, "Skipped join keys")
	}

	runForge(b, pre, gstats, opts, now, pr)

	pr.Stage("Assembling the graph")
	b.SetGraph(buildGraph(target, fstats, dstats, gstats, sstats, cstats, cpstats, tstats))

	report, body, err := b.Finish(time.Now())
	if err != nil {
		return nil, nil, err
	}
	pr.Step(stepReport, "Validated "+plural(len(report.Metrics), "metric", "metrics")+
		" against "+plural(evidenceCount(report), "evidence record", "evidence records"))

	return report, body, nil
}

// RunGraphOnly produces a schema-valid insights report whose purpose is the tech-stack graph.
// It is used by scanner subcommands after they persist SCA/SARIF results, so the org graph can
// stay fresh even when teams never run `vulnetix analyze`. It deliberately skips history,
// forge and trust collectors; scanner-driven graph runs must not pretend to have measured the
// full business/security metric set.
func RunGraphOnly(tool Tool, opts Options, pre *Preflight) (*Report, []byte, error) {
	started := time.Now()
	if pre == nil {
		opts.NoForge = true
		var err error
		pre, err = Check(context.Background(), opts)
		if err != nil {
			return nil, nil, err
		}
	}

	root := pre.Target.RootPath
	target := pre.Target
	b := NewBuilder(tool, target, started)
	pr := reporter{opts.Progress}

	var fstats *fileStats
	if opts.NoFiles {
		b.Collected(Collector{Name: "files", Status: "skipped", Reason: "disabled with --no-files"})
	} else {
		t := time.Now()
		pr.Stage("Reading files for graph")
		var err error
		fstats, err = collectFiles(b, root, nil, opts, started, pr)
		if err != nil {
			b.Collected(Collector{Name: "files", Status: "failed", Reason: err.Error(), DurationSeconds: time.Since(t).Seconds()})
			b.Diagnose(Diagnostic{Level: "warning", Collector: "files", Message: err.Error()})
		} else {
			b.Collected(Collector{Name: "files", Status: "completed", DurationSeconds: time.Since(t).Seconds()})
		}
	}

	var dstats *depStats
	if opts.NoDeps {
		b.Collected(Collector{Name: "dependencies", Status: "skipped", Reason: "disabled with --no-deps"})
	} else {
		t := time.Now()
		pr.Stage("Reading manifests for graph")
		var err error
		dstats, err = collectDeps(b, root, opts)
		if err != nil {
			b.Collected(Collector{Name: "dependencies", Status: "failed", Reason: err.Error(), DurationSeconds: time.Since(t).Seconds()})
			b.Diagnose(Diagnostic{Level: "warning", Collector: "dependencies", Message: err.Error()})
		} else {
			b.Collected(Collector{Name: "dependencies", Status: "completed", DurationSeconds: time.Since(t).Seconds()})
		}
	}

	var sstats *symbolStats
	var cstats *contractStats
	if !opts.NoFiles && fstats != nil {
		modulePath := goModulePath(filepath.Join(root, "go.mod"))

		t := time.Now()
		pr.Stage("Extracting symbols for graph")
		sstats = collectSymbols(b, root, fstats, modulePath, opts, pr)
		b.Collected(Collector{Name: "symbols", Status: "completed", DurationSeconds: time.Since(t).Seconds()})

		t = time.Now()
		pr.Stage("Finding graph join keys")
		cstats = collectContracts(b, root, fstats, dstats, target)
		b.Collected(Collector{Name: "contracts", Status: "completed", DurationSeconds: time.Since(t).Seconds()})
	} else {
		b.Collected(Collector{Name: "symbols", Status: "skipped", Reason: "the file pass did not run"})
		b.Collected(Collector{Name: "contracts", Status: "skipped", Reason: "the file pass did not run"})
	}

	b.Collected(Collector{Name: "git", Status: "skipped", Reason: "graph-only scanner run"})
	b.Collected(Collector{Name: "trust", Status: "skipped", Reason: "graph-only scanner run"})
	b.Collected(Collector{Name: "forge", Status: "skipped", Reason: "graph-only scanner run"})

	b.SetGraph(buildGraph(target, fstats, dstats, nil, sstats, cstats, nil, nil))
	return b.Finish(time.Now())
}

// evidenceCount is what the final progress line reports. It is the number that matters: every
// metric in the report is backed by these, and if the two ever disagreed the report would not
// have validated.
func evidenceCount(r *Report) int {
	n := 0
	for _, m := range r.Metrics {
		n += len(m.EvidenceRefs)
	}

	return n
}

// runForge runs the forge collector, or explains — in the report, not only on the terminal —
// why it did not.
//
// The metrics it would have produced are `null` with a reason, never zero. "We found no
// unreviewed commits" and "we could not check whether commits were reviewed" are different
// claims, and a report that cannot tell them apart is a report that will eventually be used
// to say something untrue.
func runForge(b *Builder, pre *Preflight, git *gitStats, opts Options, now time.Time, pr reporter) {
	if pre.Forge == nil {
		reason := pre.ForgeStatus
		if reason == "" {
			reason = "forge access was not available"
		}
		b.Collected(Collector{Name: "forge", Status: "skipped", Reason: reason})
		b.Diagnose(Diagnostic{Level: "warning", Collector: "forge", Message: reason})

		for _, m := range forgeMetricsWhenUnavailable() {
			b.Unmeasured(m, reason)
		}
		pr.Step(stepForge, "Skipped GitHub")

		return
	}

	t := time.Now()
	if err := collectForge(b, pre.Forge, pre.Repo, git, opts, now, pr); err != nil {
		b.Collected(Collector{Name: "forge", Status: "failed", Reason: err.Error(),
			DurationSeconds: time.Since(t).Seconds()})
		b.Diagnose(Diagnostic{Level: "error", Collector: "forge", Message: err.Error()})

		// The metrics it would have produced are still declared, as null. Dropping them entirely —
		// which is what this did — makes a failed collector look like a repository with nothing to
		// report: the numbers are not wrong, they are simply absent, and absent is the one state a
		// reader never notices.
		//
		// A collector that partially succeeded may already have emitted some of them, so only the
		// ones still missing are filled in. Emitting a metric twice would be its own kind of lie.
		for _, m := range forgeMetricsWhenUnavailable() {
			if b.Has(m.ID) {
				continue
			}
			b.Unmeasured(m, "The GitHub collector failed: "+err.Error())
		}
		pr.Step(stepForge, "GitHub failed")

		return
	}

	b.Collected(Collector{Name: "forge", Status: "completed",
		DurationSeconds: time.Since(t).Seconds()})
	pr.Step(stepForge, "Read GitHub in "+
		plural(pre.Forge.Budget().Spent(), "API call", "API calls"))
}

// forgeMetricsWhenUnavailable is the set of metrics that would have been measured. They are
// still declared, as null — a metric that is simply absent from the report is one nobody
// notices is missing, and "nobody noticed" is how a gap becomes a false clean bill of health.
func forgeMetricsWhenUnavailable() []Metric {
	return []Metric{
		{ID: "security.commits.unreviewed", Family: "security", Unit: "count",
			Name:       "Unreviewed commits on the default branch",
			Definition: "Commits on the default branch whose associated pull request has no approving review from anybody other than the author."},
		{ID: "security.pull_requests.unreviewed", Family: "security", Unit: "count",
			Name:       "Unreviewed merged pull requests",
			Definition: "Merged pull requests with no approving review from anybody other than the author."},
		{ID: "activity.pull_requests.total", Family: "activity", Unit: "count",
			Name:       "Pull requests",
			Definition: "Pull requests updated within the history window."},
		{ID: "activity.issues.total", Family: "activity", Unit: "count",
			Name:       "Issues",
			Definition: "Issues updated within the history window."},
	}
}

// buildGraph assembles the graph from what the collectors already found. The nodes here are
// the same files, dependencies and symbols the metrics counted — one source of truth, not two.
func buildGraph(target Target, f *fileStats, d *depStats, g *gitStats, s *symbolStats,
	c *contractStats, cp *couplingStats, tr *trendStats) *Graph {
	graph := &Graph{}
	seen := map[string]bool{}

	addNode := func(n Node) {
		if seen[n.ID] {
			return
		}
		seen[n.ID] = true
		graph.Nodes = append(graph.Nodes, n)
	}

	repoNode := "repo:" + target.RepoID
	addNode(Node{ID: repoNode, Kind: "repo", Name: target.RepoID})
	ensureCouplingFileNode := func(nodeID string) {
		const prefix = "file:"
		if !strings.HasPrefix(nodeID, prefix) || seen[nodeID] {
			return
		}
		path := strings.TrimPrefix(nodeID, prefix)
		addNode(Node{
			ID:   nodeID,
			Kind: "file",
			Name: filepath.Base(path),
			Path: path,
			Properties: map[string]any{
				"historical": true,
				"source":     "coupling",
			},
		})
		graph.Edges = append(graph.Edges, Edge{
			ID: "e:contains:" + path, Kind: "contains",
			From: repoNode, To: nodeID, Confidence: 1, Resolution: "heuristic",
		})
	}

	if f != nil {
		for _, file := range f.files {
			id := "file:" + file.Path
			props := map[string]any{}
			if file.Complexity != nil {
				props["complexity"] = *file.Complexity
			}
			if file.Commits > 0 {
				props["commits"] = file.Commits
				props["authors"] = file.Authors
			}
			// The complexity trajectory rides on the file's node, with the fit and the sample count
			// beside it. A slope with no R² is a number asking to be believed.
			if tr != nil {
				if t, ok := tr.byPath[file.Path]; ok {
					props["complexityTrendPerDay"] = t.SlopePerDay
					props["complexityTrendRSquared"] = t.RSquared
					props["complexityTrendSamples"] = t.Samples
					props["complexityRising"] = t.Rising
				}
			}
			addNode(Node{
				ID: id, Kind: "file", Name: filepath.Base(file.Path),
				Path: file.Path, Language: file.Language, Properties: props,
			})
			graph.Edges = append(graph.Edges, Edge{
				ID: "e:contains:" + file.Path, Kind: "contains",
				From: repoNode, To: id, Confidence: 1, Resolution: "exact",
			})
		}
	}

	// The dependency edges from the repo. The dependency NODES and their cross-repo join keys
	// are built by the contract collector, which is where every join key now lives — having two
	// places that produce them is how the count came to omit the packages.
	if d != nil {
		for _, dep := range d.deps {
			graph.Edges = append(graph.Edges, Edge{
				ID: "e:depends:" + dep.Purl, Kind: "depends_on",
				From: repoNode, To: "dependency:" + dep.Purl, Confidence: 1, Resolution: "exact",
			})
		}
	}

	if g != nil {
		for _, con := range g.contributors {
			if con.Identity.IsBot {
				continue
			}
			id := "contributor:" + con.Identity.Email
			addNode(Node{ID: id, Kind: "contributor", Name: contributorName(con)})
			graph.Edges = append(graph.Edges, Edge{
				ID: "e:authored:" + con.Identity.Email, Kind: "authored",
				From: id, To: repoNode, Confidence: 1, Resolution: "exact",
				Properties: map[string]any{"commits": con.Commits},
			})
		}
	}

	// The symbols, and the imports between files. Both resolve exactly; nothing here is
	// inferred.
	if s != nil {
		for _, n := range s.nodes {
			addNode(n)
		}
		graph.Edges = append(graph.Edges, s.edges...)
		if s.truncated || s.callTruncated {
			truncation := &GraphTruncation{}
			reasons := []string{}
			if s.truncated {
				truncation.NodesOmitted = 1
				reasons = append(reasons, fmt.Sprintf("symbol extraction stopped at the cap of %d symbols", maxSymbolsPerRepo))
			}
			if s.callTruncated {
				truncation.EdgesOmitted = 1
				reasons = append(reasons, fmt.Sprintf("call extraction stopped at the cap of %d call edges", maxCallEdgesPerRepo))
			}
			truncation.Reason = strings.Join(reasons, "; ")
			graph.Truncation = truncation
		}
	}

	// Coupling edges. Two files that keep changing together, with nothing in the code to say
	// so, is a dependency the source does not record — and the canvas can draw it.
	if cp != nil {
		for _, e := range cp.edges {
			ensureCouplingFileNode(e.From)
			ensureCouplingFileNode(e.To)
			graph.Edges = append(graph.Edges, e)
		}
	}

	// The contract nodes and the join keys that reach out of this repository. These are what
	// turn N single-repo graphs into one org graph.
	if c != nil {
		for _, n := range c.nodes {
			addNode(n)
		}
		for _, e := range c.edges {
			graph.CrossRepoEdges = append(graph.CrossRepoEdges, e)
			// A contract node hangs off the repository, so the graph is connected rather than
			// having routes and topics floating unattached to anything.
			graph.Edges = append(graph.Edges, Edge{
				ID: "e:exposes:" + e.LocalNodeID, Kind: "contains",
				From: repoNode, To: e.LocalNodeID, Confidence: 1, Resolution: "exact",
			})
		}
	}

	return graph
}

func contributorName(c *ContributorRecord) string {
	if c.Identity.Name != "" {
		return c.Identity.Name
	}

	return c.Identity.Email
}

// purlWithoutVersion is the cross-repo join key for a package.
//
// The version is deliberately dropped. Repo A depending on shared@1.2.0 and repo B publishing
// shared@1.3.0 are still the same relationship — an org graph that only linked exact-version
// matches would show almost no edges at all, and the ones it did show would be an accident of
// release timing.
func purlWithoutVersion(purl string) string {
	if i := strings.LastIndex(purl, "@"); i > 0 {
		return purl[:i]
	}

	return purl
}

func purlName(purl string) string {
	s := purlWithoutVersion(purl)
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}

	return s
}

// ─── repository identity ─────────────────────────────────────────────────────────

var scpLike = regexp.MustCompile(`^([^@]+@)?([^:]+):(.+?)(\.git)?$`)

func fillTargetFromGit(t *Target, repo *git.Repository, root string) {
	if head, err := repo.Head(); err == nil {
		t.HeadCommit = head.Hash().String()
		t.DefaultBranch = head.Name().Short()
		if c, cerr := repo.CommitObject(head.Hash()); cerr == nil {
			t.HeadCommittedAt = c.Committer.When.UTC().Format(time.RFC3339)
		}
	}

	remotes, err := repo.Remotes()
	if err != nil || len(remotes) == 0 {
		t.RepoID = "local~~" + filepath.Base(root)

		return
	}

	remoteURL := ""
	for _, r := range remotes {
		if r.Config().Name == "origin" && len(r.Config().URLs) > 0 {
			remoteURL = r.Config().URLs[0]

			break
		}
	}
	if remoteURL == "" && len(remotes[0].Config().URLs) > 0 {
		remoteURL = remotes[0].Config().URLs[0]
	}
	t.RemoteURL = remoteURL

	host, owner, name := parseRemote(remoteURL)
	if host == "" || name == "" {
		t.RepoID = "local~~" + filepath.Base(root)

		return
	}
	t.RepoID = fmt.Sprintf("%s~%s~%s", host, owner, name)
	t.OrgKey = fmt.Sprintf("%s~%s", host, owner)
}

// parseRemote turns a git remote into (host, owner, name) — the three parts of the repoId that
// every cross-repo join keys on. Handles both URL and scp-like forms, because a repo cloned
// over SSH and the same repo cloned over HTTPS must produce the same identity or the org graph
// will show them as two different repositories.
func parseRemote(remote string) (host, owner, name string) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", "", ""
	}
	remote = strings.TrimSuffix(remote, ".git")

	if strings.Contains(remote, "://") {
		u, err := url.Parse(remote)
		if err != nil {
			return "", "", ""
		}
		host = u.Hostname()
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) >= 2 {
			owner = strings.Join(parts[:len(parts)-1], "/")
			name = parts[len(parts)-1]
		} else if len(parts) == 1 {
			name = parts[0]
		}

		return host, owner, name
	}

	if m := scpLike.FindStringSubmatch(remote); m != nil {
		host = m[2]
		parts := strings.Split(strings.Trim(m[3], "/"), "/")
		if len(parts) >= 2 {
			owner = strings.Join(parts[:len(parts)-1], "/")
			name = parts[len(parts)-1]
		} else if len(parts) == 1 {
			name = parts[0]
		}

		return host, owner, name
	}

	return "", "", ""
}
