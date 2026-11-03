package cmd

// `vulnetix gha publish advisories`: draft GitHub repository security
// advisories for this repository's own SAST findings.
//
// Scope: first-party SAST findings (kind sast) at or above --min-severity,
// excluding suppressed findings, findings in the test suite and findings
// with a confidence gap. One advisory per rule and CWE set, worst first,
// capped at --max. The package is this repository's own, read from its
// manifest. Each advisory carries <!-- vulnetix-advisory:<hash> --> so a later
// run updates its draft instead of adding another; an advisory a maintainer
// has published or closed is left alone. Nothing is ever published.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v4/internal/github"
	"github.com/vulnetix/cli/v4/internal/sast"
)

var (
	advRepo        string
	advPath        string
	advSARIF       []string
	advMinSeverity string
	advMax         int
	advDryRun      bool
)

var ghaPublishAdvisoriesCmd = &cobra.Command{
	Use:   "advisories",
	Short: "Draft GitHub repository security advisories for this repository's SAST findings",
	Long: `Draft GitHub repository security advisories for this repository's own SAST
findings (POST /repos/{owner}/{repo}/security-advisories).

One draft per rule and CWE, for findings at or above --min-severity, worst
first, at most --max. Suppressed findings, findings in the test suite and
findings with a confidence gap are left out. The affected package is this
repository's own, from its manifest (package.json, go.mod, pyproject.toml,
Cargo.toml, composer.json). Severity is set; a CVSS vector never is.

A marker in each description ties it to its finding group: a later run updates
the matching draft rather than adding one, and leaves an advisory that has been
published or closed alone. Advisories are never published by this command.

The token needs repository advisories write: a fine-grained PAT or a GitHub
App installation token. The workflow GITHUB_TOKEN cannot create advisories.`,
	Example: `  GITHUB_TOKEN=$ADVISORY_PAT vulnetix gha publish advisories
  vulnetix gha publish advisories --min-severity critical --max 3 --dry-run`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		files := advSARIF
		if len(files) == 0 {
			files = []string{filepath.Join(advPath, ".vulnetix", "sast.sarif")}
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
		return runAdvisoriesPublish(cmd.Context(), advisoriesOptions{
			Root: advPath, Repo: advRepo, Logs: logs, MinSeverity: advMinSeverity, Max: advMax, DryRun: advDryRun,
		}, os.Stderr)
	},
}

type advisoriesOptions struct {
	Root, Repo  string
	Logs        []*sast.SARIFLog
	MinSeverity string
	Max         int
	DryRun      bool
	Client      *github.Client
}

// advisoryGroup is one rule and CWE set's findings.
type advisoryGroup struct {
	RuleID, Name, Description, HelpURI string
	Severity                           string
	CWEs                               []string
	Locations                          []string
}

func (g advisoryGroup) key() string { return g.RuleID + "|" + strings.Join(g.CWEs, ",") }

func (g advisoryGroup) hash() string {
	sum := sha256.Sum256([]byte(g.key()))
	return hex.EncodeToString(sum[:8])
}

var advisorySeverityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

var cweNum = regexp.MustCompile(`(?i)^cwe-(\d+)$`)

// advisoryGroups selects and groups the findings that qualify.
func advisoryGroups(logs []*sast.SARIFLog, minSeverity string, max int) []advisoryGroup {
	floor := advisorySeverityRank[strings.ToLower(minSeverity)]
	if floor == 0 {
		floor = advisorySeverityRank["high"]
	}
	groups := map[string]*advisoryGroup{}
	for _, l := range logs {
		if l == nil {
			continue
		}
		for ri := range l.Runs {
			run := &l.Runs[ri]
			runKind := sast.KindOfRun(run)
			rules := map[string]sast.SARIFReportingDescriptor{}
			for _, d := range run.Tool.Driver.Rules {
				rules[d.ID] = d
			}
			for _, r := range run.Results {
				kind := runKind
				if k, ok := r.Properties["vulnetix/kind"].(string); ok && k != "" {
					kind = sast.CategoryKind(k)
				}
				if kind != "sast" || len(r.Suppressions) > 0 ||
					r.Properties["vulnetix/test-suite"] == true || r.Properties["vulnetix/confidence-gap"] == true {
					continue
				}
				sev, _ := r.Properties["severity"].(string)
				sev = strings.ToLower(sev)
				if advisorySeverityRank[sev] < floor {
					continue
				}
				d := rules[r.RuleID]
				g := advisoryGroup{RuleID: r.RuleID, Name: d.Name, HelpURI: d.HelpURI, Severity: sev, CWEs: ruleCWEs(d)}
				if d.ShortDescription != nil {
					g.Description = d.ShortDescription.Text
				}
				key := g.key()
				cur, ok := groups[key]
				if !ok {
					cur = &g
					groups[key] = cur
				}
				if advisorySeverityRank[sev] > advisorySeverityRank[cur.Severity] {
					cur.Severity = sev
				}
				if len(r.Locations) > 0 && r.Locations[0].PhysicalLocation != nil && r.Locations[0].PhysicalLocation.ArtifactLocation != nil {
					loc := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
					if reg := r.Locations[0].PhysicalLocation.Region; reg != nil && reg.StartLine > 0 {
						loc = fmt.Sprintf("%s:%d", loc, reg.StartLine)
					}
					cur.Locations = append(cur.Locations, loc)
				}
			}
		}
	}
	out := make([]advisoryGroup, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.Locations)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if advisorySeverityRank[a.Severity] != advisorySeverityRank[b.Severity] {
			return advisorySeverityRank[a.Severity] > advisorySeverityRank[b.Severity]
		}
		if len(a.Locations) != len(b.Locations) {
			return len(a.Locations) > len(b.Locations)
		}
		return a.key() < b.key()
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// ruleCWEs reads a rule's CWE ids (CWE-89) from its cwe property or its
// external/cwe/cwe-N tags.
func ruleCWEs(d sast.SARIFReportingDescriptor) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimPrefix(strings.ToLower(s), "external/cwe/")
		if m := cweNum.FindStringSubmatch(s); m != nil {
			id := "CWE-" + m[1]
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	for _, key := range []string{"cwe", "tags"} {
		switch v := d.Properties[key].(type) {
		case []string:
			for _, s := range v {
				add(s)
			}
		case []any:
			for _, s := range v {
				if str, ok := s.(string); ok {
					add(str)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// repoPackage reads the repository's own package from its root manifest. A
// repository with none is reported under the "other" ecosystem by its name.
func repoPackage(root, repo string) github.AdvisoryPackage {
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return ""
		}
		return string(b)
	}
	if s := read("package.json"); s != "" {
		var p struct{ Name string }
		if json.Unmarshal([]byte(s), &p) == nil && p.Name != "" {
			return github.AdvisoryPackage{Ecosystem: "npm", Name: p.Name}
		}
	}
	if s := read("go.mod"); s != "" {
		if m := regexp.MustCompile(`(?m)^module\s+(\S+)`).FindStringSubmatch(s); m != nil {
			return github.AdvisoryPackage{Ecosystem: "go", Name: m[1]}
		}
	}
	if s := read("Cargo.toml"); s != "" {
		if m := regexp.MustCompile(`(?ms)^\[package\].*?^name\s*=\s*"([^"]+)"`).FindStringSubmatch(s); m != nil {
			return github.AdvisoryPackage{Ecosystem: "rust", Name: m[1]}
		}
	}
	if s := read("pyproject.toml"); s != "" {
		if m := regexp.MustCompile(`(?ms)^\[(?:project|tool\.poetry)\].*?^name\s*=\s*"([^"]+)"`).FindStringSubmatch(s); m != nil {
			return github.AdvisoryPackage{Ecosystem: "pip", Name: m[1]}
		}
	}
	if s := read("composer.json"); s != "" {
		var p struct{ Name string }
		if json.Unmarshal([]byte(s), &p) == nil && p.Name != "" {
			return github.AdvisoryPackage{Ecosystem: "composer", Name: p.Name}
		}
	}
	return github.AdvisoryPackage{Ecosystem: "other", Name: repo}
}

const maxAdvisoryLocations = 25

func advisoryRequest(g advisoryGroup, pkg github.AdvisoryPackage) github.AdvisoryRequest {
	title := g.Name
	if title == "" {
		title = g.RuleID
	}
	var d strings.Builder
	if g.Description != "" {
		fmt.Fprintf(&d, "%s\n\n", g.Description)
	}
	fmt.Fprintf(&d, "Vulnetix SAST rule `%s` reported this in %d place(s):\n\n", g.RuleID, len(g.Locations))
	for i, l := range g.Locations {
		if i == maxAdvisoryLocations {
			fmt.Fprintf(&d, "- and %d more\n", len(g.Locations)-maxAdvisoryLocations)
			break
		}
		fmt.Fprintf(&d, "- `%s`\n", l)
	}
	if g.HelpURI != "" {
		fmt.Fprintf(&d, "\nRule documentation: %s\n", g.HelpURI)
	}
	fmt.Fprintf(&d, "\nThis draft was created by `vulnetix gha publish advisories` and is never published automatically. Review it, then publish, edit or close it.\n\n%s\n", github.AdvisoryMarker(g.hash()))
	summary := "[Vulnetix] " + title
	if len(summary) > 1024 {
		summary = summary[:1024]
	}
	return github.AdvisoryRequest{
		Summary:         summary,
		Description:     d.String(),
		Vulnerabilities: []github.AdvisoryVulnerability{{Package: pkg}},
		CWEIDs:          g.CWEs,
		Severity:        g.Severity,
	}
}

func runAdvisoriesPublish(ctx context.Context, o advisoriesOptions, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if o.Root == "" {
		o.Root = "."
	}
	groups := advisoryGroups(o.Logs, o.MinSeverity, o.Max)
	if len(groups) == 0 {
		fmt.Fprintf(w, "  advisories: no SAST finding at or above %s qualifies\n", o.MinSeverity)
		return nil
	}
	repo := o.Repo
	if repo == "" {
		t, err := github.ResolveTarget(o.Root, "", "x", "x")
		if err != nil && !o.DryRun {
			return err
		}
		repo = t.Repo
	}
	pkg := repoPackage(o.Root, repo)
	if o.DryRun {
		for _, g := range groups {
			req := advisoryRequest(g, pkg)
			fmt.Fprintf(w, "  advisories: would draft %q (%s, %s, %d location(s))\n", req.Summary, req.Severity, strings.Join(req.CWEIDs, ","), len(g.Locations))
		}
		return nil
	}
	client := o.Client
	if client == nil {
		tok, _, err := github.ResolveToken()
		if err != nil {
			return err
		}
		client = github.NewClient(tok)
	}
	existing, err := client.ListAdvisories(ctx, repo)
	if err != nil {
		return fmt.Errorf("advisories: %w%s", err, permissionHint(err, "repository advisories write (a PAT or GitHub App)"))
	}
	byMarker := map[string]github.RepositoryAdvisory{}
	for _, a := range existing {
		if h := github.MarkerOf(a.Description); h != "" {
			byMarker[h] = a
		}
	}
	var failed []string
	for _, g := range groups {
		req := advisoryRequest(g, pkg)
		prev, ok := byMarker[g.hash()]
		switch {
		case ok && prev.State != "draft":
			fmt.Fprintf(w, "  advisories: %s is %s; left alone (%s)\n", prev.GHSAID, prev.State, g.RuleID)
		case ok:
			if _, err := client.UpdateAdvisory(ctx, repo, prev.GHSAID, req); err != nil {
				failed = append(failed, g.RuleID)
				fmt.Fprintf(w, "  advisories: update %s: %v\n", prev.GHSAID, err)
				continue
			}
			fmt.Fprintf(w, "  advisories: updated draft %s (%s)\n", prev.GHSAID, g.RuleID)
		default:
			a, err := client.CreateAdvisory(ctx, repo, req)
			if err != nil {
				failed = append(failed, g.RuleID)
				fmt.Fprintf(w, "  advisories: create for %s: %v%s\n", g.RuleID, err, permissionHint(err, "repository advisories write (a PAT or GitHub App)"))
				continue
			}
			fmt.Fprintf(w, "  advisories: drafted %s (%s) %s\n", a.GHSAID, g.RuleID, a.HTMLURL)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("advisories failed for %s", strings.Join(failed, ", "))
	}
	return nil
}

func init() {
	ghaPublishAdvisoriesCmd.Flags().StringVar(&advRepo, "repo", "", "Repository owner/name (default: GITHUB_REPOSITORY, then the git remote)")
	ghaPublishAdvisoriesCmd.Flags().StringVar(&advPath, "path", ".", "Repository root (its manifest names the affected package)")
	ghaPublishAdvisoriesCmd.Flags().StringArrayVar(&advSARIF, "sarif", nil, "SARIF file to read (repeatable; default: <path>/.vulnetix/sast.sarif)")
	ghaPublishAdvisoriesCmd.Flags().StringVar(&advMinSeverity, "min-severity", "high", "Lowest severity that gets an advisory: critical, high, medium or low")
	ghaPublishAdvisoriesCmd.Flags().IntVar(&advMax, "max", 10, "Most advisories to draft or update in one run")
	ghaPublishAdvisoriesCmd.Flags().BoolVar(&advDryRun, "dry-run", false, "Print what would be drafted and call nothing")
	ghaPublishCmd.AddCommand(ghaPublishAdvisoriesCmd)
}
