// Command efficacy measures how accurate `vulnetix scan` is on real open-source
// projects.
//
// It clones a set of repositories, runs the SCA pass on each, and compares every
// finding with an independent oracle: OSV's answer for the exact package version.
// It also runs checks that need no oracle, because some failures are visible from
// the report alone (a fix older than the installed version, a "no fix" whose own
// range names one, an impossible group).
//
//	go run ./tools/efficacy -bin ./vulnetix -work /tmp/efficacy
//	go run ./tools/efficacy -bin ./vulnetix -work /tmp/efficacy -only fastapi,requests
//
// The oracle is a cross-check, not the truth: OSV and Vulnetix draw on different
// sources. A disagreement is classified, never just counted, so that a real
// false positive (the advisory's own range excludes this version) is separated
// from a difference in coverage.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/internal/versions"
)

type repo struct {
	Name string
	URL  string
	// Path narrows the scan to a subdirectory (monorepos).
	Path string
	// Depth overrides the default directory depth.
	Depth int
}

var defaultRepos = []repo{
	{"kospex", "https://github.com/kospex/kospex.git", "", 3},
	{"fastapi", "https://github.com/fastapi/fastapi.git", "", 3},
	{"flask", "https://github.com/pallets/flask.git", "", 3},
	{"django", "https://github.com/django/django.git", "", 3},
	{"requests", "https://github.com/psf/requests.git", "", 3},
	{"express", "https://github.com/expressjs/express.git", "", 3},
	{"lodash", "https://github.com/lodash/lodash.git", "", 3},
	{"react", "https://github.com/facebook/react.git", "", 3},
	{"vue", "https://github.com/vuejs/core.git", "", 3},
	{"gin", "https://github.com/gin-gonic/gin.git", "", 3},
	{"cobra", "https://github.com/spf13/cobra.git", "", 3},
	{"ripgrep", "https://github.com/BurntSushi/ripgrep.git", "", 3},
	{"tokio", "https://github.com/tokio-rs/tokio.git", "", 3},
	{"rails", "https://github.com/rails/rails.git", "", 3},
	{"laravel", "https://github.com/laravel/laravel.git", "", 3},
	{"spring-petclinic", "https://github.com/spring-projects/spring-petclinic.git", "", 3},
	{"jenkins", "https://github.com/jenkinsci/jenkins.git", "", 3},
}

// ── report shape (vulnetix/report/v1) ──────────────────────────────────────

type advisory struct {
	ID            string `json:"id"`
	Severity      string `json:"severity"`
	Verdict       string `json:"verdict"`
	Basis         string `json:"basis"`
	Range         string `json:"range"`
	FixedIn       string `json:"fixedIn"`
	FixedInSource string `json:"fixedInSource"`
	Fix           string `json:"fix"`
	FixSource     string `json:"fixSource"`
	Detail        string `json:"detail"`
	// Aliases are the identifiers the report folded into this row.
	Aliases []string `json:"aliases"`
}

type pkg struct {
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Ecosystem  string     `json:"ecosystem"`
	Purl       string     `json:"purl"`
	Source     string     `json:"source"`
	Group      string     `json:"group"`
	Fix        fix        `json:"fix"`
	Advisories []advisory `json:"advisories"`
	RuledOut   []advisory `json:"ruledOut"`
}

type fix struct {
	State  string `json:"state"`
	Target string `json:"target"`
	Clears int    `json:"clears"`
	Of     int    `json:"of"`
}

type vxReport struct {
	Counts struct {
		Advisories int            `json:"advisories"`
		Packages   int            `json:"packages"`
		ByGroup    map[string]int `json:"byGroup"`
	} `json:"counts"`
	Meta struct {
		ScannedPackages int `json:"scannedPackages"`
	} `json:"meta"`
	Packages []pkg `json:"packages"`
}

// ── OSV ────────────────────────────────────────────────────────────────────

type osvRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Purl      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

type osvClient struct {
	cache string
	http  *http.Client
	mu    sync.Mutex
}

func newOSV(cache string) *osvClient {
	_ = os.MkdirAll(cache, 0o755)
	return &osvClient{cache: cache, http: &http.Client{Timeout: 60 * time.Second}}
}

func (o *osvClient) do(method, url string, body []byte) ([]byte, int, error) {
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		req, _ := http.NewRequest(method, url, bytes.NewReader(body))
		resp, err := o.http.Do(req)
		if err != nil {
			last = err
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
			continue
		}
		return b, resp.StatusCode, nil
	}
	return nil, 0, last
}

// queryBatch returns, for each purl, the OSV ids affecting that exact version.
func (o *osvClient) queryBatch(purls []string) (map[string][]string, error) {
	out := map[string][]string{}
	type q struct {
		Package struct {
			Purl string `json:"purl"`
		} `json:"package"`
		PageToken string `json:"page_token,omitempty"`
	}
	pending := make([]q, 0, len(purls))
	owner := make([]string, 0, len(purls))
	for _, p := range purls {
		var x q
		x.Package.Purl = p
		pending = append(pending, x)
		owner = append(owner, p)
	}
	for len(pending) > 0 {
		n := min(500, len(pending))
		batch, owners := pending[:n], owner[:n]
		pending, owner = pending[n:], owner[n:]
		body, _ := json.Marshal(map[string]any{"queries": batch})
		raw, code, err := o.do("POST", "https://api.osv.dev/v1/querybatch", body)
		if err != nil || code != 200 {
			return nil, fmt.Errorf("querybatch: %v (HTTP %d) %.200s", err, code, raw)
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
				NextPageToken string `json:"next_page_token"`
			} `json:"results"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, err
		}
		for i, r := range resp.Results {
			for _, v := range r.Vulns {
				out[owners[i]] = append(out[owners[i]], v.ID)
			}
			if r.NextPageToken != "" {
				x := batch[i]
				x.PageToken = r.NextPageToken
				pending = append(pending, x)
				owner = append(owner, owners[i])
			}
		}
	}
	return out, nil
}

// vuln fetches one OSV record, caching it on disk. A missing record is cached as
// an empty file so it is not asked for again.
func (o *osvClient) vuln(id string) *osvRecord {
	path := filepath.Join(o.cache, strings.NewReplacer("/", "_", ":", "_").Replace(id)+".json")
	o.mu.Lock()
	data, err := os.ReadFile(path)
	o.mu.Unlock()
	if err != nil {
		raw, code, derr := o.do("GET", "https://api.osv.dev/v1/vulns/"+id, nil)
		if derr != nil {
			return nil
		}
		if code != 200 {
			raw = []byte{}
		}
		o.mu.Lock()
		_ = os.WriteFile(path, raw, 0o644)
		o.mu.Unlock()
		data = raw
	}
	if len(data) == 0 {
		return nil
	}
	var r osvRecord
	if json.Unmarshal(data, &r) != nil {
		return nil
	}
	return &r
}

var pyNorm = regexp.MustCompile(`[-_.]+`)

func normName(eco, name string) string {
	name = strings.ToLower(name)
	if strings.EqualFold(eco, "pypi") {
		return pyNorm.ReplaceAllString(name, "-")
	}
	return name
}

// osvVerdict evaluates an OSV record against one package version.
// Returns "affected", "unaffected" or "unknown" (no comparable data).
func osvVerdict(r *osvRecord, eco, name, version string) (string, string) {
	v, err := versions.Parse(version)
	if err != nil {
		return "unknown", "unparseable installed version"
	}
	want := normName(eco, name)
	sawPackage, sawComparable := false, false
	for _, a := range r.Affected {
		got := normName(a.Package.Ecosystem, a.Package.Name)
		if got != want && !strings.Contains(strings.ToLower(a.Package.Purl), "/"+want) {
			continue
		}
		sawPackage = true
		for _, ver := range a.Versions {
			if ver == version {
				return "affected", "listed in versions[]"
			}
		}
		for _, rg := range a.Ranges {
			if rg.Type == "GIT" {
				continue
			}
			sawComparable = true
			affected := false
			var intro *versions.Version
			for _, e := range rg.Events {
				switch {
				case e.Introduced != "":
					if e.Introduced == "0" {
						z, _ := versions.Parse("0")
						intro = &z
					} else if iv, err := versions.Parse(e.Introduced); err == nil {
						intro = &iv
					}
					if intro != nil && versions.Compare(v, *intro) >= 0 {
						affected = true
					}
				case e.Fixed != "":
					if fv, err := versions.Parse(e.Fixed); err == nil && versions.Compare(v, fv) >= 0 {
						affected = false
					}
				case e.LastAffected != "":
					if lv, err := versions.Parse(e.LastAffected); err == nil && versions.Compare(v, lv) > 0 {
						affected = false
					}
				}
			}
			if affected {
				return "affected", "inside an OSV range"
			}
		}
	}
	switch {
	case !sawPackage:
		return "unknown", "OSV record names no such package"
	case !sawComparable:
		return "unknown", "OSV ranges are git commits"
	}
	return "unaffected", "outside every OSV range"
}

// ── comparison ─────────────────────────────────────────────────────────────

type finding struct {
	Repo, Purl, ID, Class, Detail string
}

type repoResult struct {
	Name                      string
	Packages, Counted         int
	Scanned                   int
	Matched, FP, FN, OSVTotal int
	OSVMatched, Mislabeled    int
	Findings                  []finding
	Problems                  []finding
	ScanErr                   string
	Groups                    map[string]int
	UnverifiedAdvisories      int
	OSVRulesOut               int // OSV says affected, we ruled it out
}

func advisoryClosure(o *osvClient, a advisory) map[string]bool {
	set := closure(o, a.ID)
	for _, al := range a.Aliases {
		for k := range closure(o, al) {
			set[k] = true
		}
	}
	return set
}

func closure(o *osvClient, id string) map[string]bool {
	set := map[string]bool{strings.ToUpper(id): true}
	if r := o.vuln(id); r != nil {
		set[strings.ToUpper(r.ID)] = true
		for _, a := range r.Aliases {
			set[strings.ToUpper(a)] = true
		}
	}
	return set
}

func intersects(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

func compare(name string, rep *vxReport, allPurls []string, o *osvClient) repoResult {
	// The report lists only packages that have findings. A clean package is one
	// the tool said nothing about, which is exactly where a missed vulnerability
	// hides, so every scanned package is added and asked about.
	have := map[string]bool{}
	for _, p := range rep.Packages {
		have[normPlatformPurl(p.Purl)] = true
	}
	var nonVersions []finding
	for _, p := range allPurls {
		p = normPlatformPurl(p)
		if !have[p] {
			have[p] = true
			// A component whose "version" is not a version (latest, catalog:, link:,
			// workspace:) is a package nobody resolved. The oracle cannot answer for it,
			// and the SBOM should not claim a version for it.
			if at := strings.LastIndex(p, "@"); at > 0 {
				if _, perr := versions.Parse(purlDecode(p[at+1:])); perr != nil {
					nonVersions = append(nonVersions, finding{name, p, "", "C-non-version-component", "the SBOM lists a version the tool cannot compare: " + purlDecode(p[at+1:])})
					continue
				}
			}
			rep.Packages = append(rep.Packages, pkg{Purl: p, Group: "not_affected"})
		}
	}
	res := repoResult{Name: name, Groups: rep.Counts.ByGroup, Packages: len(rep.Packages), Scanned: rep.Meta.ScannedPackages}
	res.Problems = append(res.Problems, nonVersions...)

	// Oracle queries cover every scanned package we have a purl for, including the
	// ones we reported clean: a false negative is a package we said nothing about.
	var purls []string
	seen := map[string]bool{}
	for _, p := range rep.Packages {
		if p.Purl != "" && !seen[p.Purl] {
			seen[p.Purl] = true
			purls = append(purls, p.Purl)
		}
	}
	osvHits, err := o.queryBatch(purls)
	if err != nil {
		res.ScanErr = "osv: " + err.Error()
		return res
	}

	// Pre-warm the vuln cache concurrently.
	ids := map[string]bool{}
	for _, v := range osvHits {
		for _, id := range v {
			ids[id] = true
		}
	}
	for _, p := range rep.Packages {
		for _, a := range append(append([]advisory{}, p.Advisories...), p.RuledOut...) {
			ids[a.ID] = true
			for _, al := range a.Aliases {
				ids[al] = true
			}
		}
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			o.vuln(id)
		}(id)
	}
	wg.Wait()

	for _, p := range rep.Packages {
		osvIDs := osvHits[p.Purl]
		osvSets := make([]map[string]bool, len(osvIDs))
		for i, id := range osvIDs {
			osvSets[i] = closure(o, id)
		}
		res.OSVTotal += len(osvIDs)

		// Everything we said about this package, counted or ruled out.
		ours := p.Advisories
		oursSets := make([]map[string]bool, len(ours))
		for i, a := range ours {
			oursSets[i] = advisoryClosure(o, a)
		}
		ruled := p.RuledOut
		ruledSets := make([]map[string]bool, len(ruled))
		for i, a := range ruled {
			ruledSets[i] = advisoryClosure(o, a)
		}
		res.Counted += len(ours)

		matchedOSV := make([]bool, len(osvIDs))
		for i, a := range ours {
			hit := false
			for j, os := range osvSets {
				if intersects(oursSets[i], os) {
					hit = true
					matchedOSV[j] = true
				}
			}
			if a.Verdict == "unverified" {
				res.UnverifiedAdvisories++
			}
			if hit {
				res.Matched++
				continue
			}
			// The right vulnerability under the wrong identifier: OSV has a record for
			// this package fixed in the very version our range names. That is a
			// labelling defect, counted apart from a finding with no basis at all.
			if fixedMatchesOSV(o, a, osvIDs, p) {
				res.Mislabeled++
				res.Findings = append(res.Findings, finding{name, p.Purl, a.ID, "ID-mislabel",
					fmt.Sprintf("same fix (%s) as an OSV record for this package, under a different identifier", a.FixedIn)})
				continue
			}
			res.FP++
			class, detail := classifyFP(o, a, p)
			res.Findings = append(res.Findings, finding{name, p.Purl, a.ID, class, detail})
		}
		for _, m := range matchedOSV {
			if m {
				res.OSVMatched++
			}
		}
		for j, id := range osvIDs {
			if matchedOSV[j] {
				continue
			}
			// Did we rule it out on purpose?
			ruledOut := false
			for i := range ruled {
				if intersects(ruledSets[i], osvSets[j]) {
					ruledOut = true
					res.OSVRulesOut++
					res.Findings = append(res.Findings, finding{name, p.Purl, id, "FN-ruled-out",
						fmt.Sprintf("OSV lists it; we ruled it out: %s", ruled[i].Detail)})
				}
			}
			if ruledOut {
				continue
			}
			res.FN++
			res.Findings = append(res.Findings, finding{name, p.Purl, id, "FN-missed", osvSummary(o, id)})
		}
		if p.Name != "" { // a package the report did not list has nothing to check
			res.Problems = append(res.Problems, consistency(name, p)...)
			res.Problems = append(res.Problems, fixChecks(name, p, osvIDs, o)...)
		}
	}
	return res
}

func osvSummary(o *osvClient, id string) string {
	r := o.vuln(id)
	if r == nil {
		return "no OSV record"
	}
	return fmt.Sprintf("aliases %v", r.Aliases)
}

// classifyFP says why a finding OSV does not return for this version is, or is
// not, a real false positive.
func classifyFP(o *osvClient, a advisory, p pkg) (string, string) {
	// Judge across every alias of the advisory: the CVE record often names no
	// package while its GHSA or PYSEC twin carries the ranges.
	var best *osvRecord
	bestV, bestWhy := "", ""
	for id := range closure(o, a.ID) {
		rec := o.vuln(id)
		if rec == nil {
			continue
		}
		v, why := osvVerdict(rec, p.Ecosystem, p.Name, p.Version)
		if bestV == "" || (bestV == "unknown" && v != "unknown") || (v == "affected" && bestV != "affected") {
			best, bestV, bestWhy = rec, v, why
		}
	}
	r := o.vuln(a.ID)
	if best != nil {
		r = best
	}
	if r == nil {
		// Look through aliases: an NVD-only CVE may have a GHSA the OSV knows.
		return "FP-unknown-to-osv", fmt.Sprintf("verdict=%s basis=%s range=%q", a.Verdict, a.Basis, a.Range)
	}
	if r.Withdrawn != "" {
		return "FP-withdrawn", "OSV marks this advisory withdrawn " + r.Withdrawn
	}
	v, why := bestV, bestWhy
	if best == nil {
		v, why = osvVerdict(r, p.Ecosystem, p.Name, p.Version)
	}
	switch v {
	case "unaffected":
		// Saying "affected" against the record is a false claim. Saying "unverified"
		// is the tool declining to claim: it counts, but it is not a wrong answer.
		if a.Verdict == "unverified" {
			return "FP-flagged-unverified", fmt.Sprintf("OSV's record for %s excludes %s (%s); we said unverified (%s): %q",
				a.ID, p.Version, why, a.Basis, a.Range)
		}
		return "FP-REAL", fmt.Sprintf("OSV's own record for %s excludes %s (%s); we said verdict=%s basis=%s range=%q",
			a.ID, p.Version, why, a.Verdict, a.Basis, a.Range)
	case "affected":
		return "FP-osv-record-affected", "OSV's record says affected but querybatch omitted it"
	}
	return "FP-unverifiable", fmt.Sprintf("%s; verdict=%s basis=%s range=%q", why, a.Verdict, a.Basis, a.Range)
}

// consistency runs checks that need no oracle.
func consistency(repo string, p pkg) []finding {
	var out []finding
	bad := func(id, class, detail string) {
		out = append(out, finding{repo, p.Purl, id, class, detail})
	}
	if _, perr := versions.Parse(p.Version); perr != nil && p.Version != "" {
		bad("", "C-unparseable-installed", fmt.Sprintf("%s version %q cannot be compared", p.Ecosystem, p.Version))
	}
	if p.Name == "" || p.Version == "" || p.Purl == "" {
		bad("", "C-empty-field", fmt.Sprintf("name=%q version=%q purl=%q", p.Name, p.Version, p.Purl))
	}
	iv, ierr := versions.Parse(p.Version)
	for _, a := range p.Advisories {
		if a.ID == "" {
			bad("", "C-blank-id", "advisory with no identifier")
		}
		// A counted advisory whose own fixed-in is at or below the installed version.
		if ierr == nil && a.FixedIn != "" && a.FixedInSource == "advisory" && a.Verdict == "affected" {
			if fv, err := versions.Parse(a.FixedIn); err == nil && versions.Compare(iv, fv) >= 0 {
				bad(a.ID, "C-fixed-before-installed", fmt.Sprintf("counted as affected but fixed in %s <= installed %s", a.FixedIn, p.Version))
			}
		}
		// A fix recommendation that is not newer than what is installed.
		if ierr == nil && a.Fix != "" {
			if fv, err := versions.Parse(a.Fix); err == nil && versions.Compare(fv, iv) <= 0 && a.Verdict == "affected" {
				bad(a.ID, "C-fix-not-newer", fmt.Sprintf("recommended fix %s is not newer than installed %s", a.Fix, p.Version))
			}
		}
		if a.Verdict == "" {
			bad(a.ID, "C-no-verdict", "")
		}
	}
	if ierr == nil && p.Fix.Target != "" {
		if fv, err := versions.Parse(p.Fix.Target); err == nil && versions.Compare(fv, iv) <= 0 {
			bad("", "C-package-fix-not-newer", fmt.Sprintf("package fix target %s <= installed %s", p.Fix.Target, p.Version))
		}
	}
	if len(p.Advisories) == 0 && p.Group != "not_affected" {
		bad("", "C-empty-group", "package with no counted advisories is in group "+p.Group)
	}
	if p.Fix.State == "none" {
		for _, a := range p.Advisories {
			if a.FixedIn != "" && a.FixedInSource == "advisory" && a.Verdict == "affected" {
				bad(a.ID, "C-no-fix-but-range-names-one", "package says no fix; advisory range fixes in "+a.FixedIn)
			}
		}
	}
	return out
}

// ── driver ─────────────────────────────────────────────────────────────────

func run(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

func main() {
	bin := flag.String("bin", "./vulnetix", "path to the vulnetix binary")
	work := flag.String("work", "/tmp/efficacy", "working directory for clones and caches")
	only := flag.String("only", "", "comma-separated repo names to run")
	reposFile := flag.String("repos", "", "JSON file of extra repos: [{\"Name\":..,\"URL\":..}]")
	out := flag.String("out", "", "write the full JSON result here")
	maxShow := flag.Int("show", 40, "max findings to print per class")
	maxWrong := flag.Int("max-wrong", -1, "exit non-zero when more than this many findings are wrongly claimed affected (FP-REAL); -1 disables")
	minRecall := flag.Float64("min-recall", 0, "exit non-zero when recall against OSV falls below this percentage")
	flag.Parse()

	repos := defaultRepos
	if *reposFile != "" {
		b, err := os.ReadFile(*reposFile)
		if err != nil {
			fatal(err)
		}
		var extra []repo
		if err := json.Unmarshal(b, &extra); err != nil {
			fatal(err)
		}
		repos = append(repos, extra...)
	}
	if *only != "" {
		want := map[string]bool{}
		for _, n := range strings.Split(*only, ",") {
			want[strings.TrimSpace(n)] = true
		}
		var keep []repo
		for _, r := range repos {
			if want[r.Name] {
				keep = append(keep, r)
			}
		}
		repos = keep
	}
	_ = os.MkdirAll(*work, 0o755)
	osv := newOSV(filepath.Join(*work, "osv-cache"))

	var results []repoResult
	for _, r := range repos {
		dir := filepath.Join(*work, "repos", r.Name)
		if _, err := os.Stat(dir); err != nil {
			_ = os.MkdirAll(filepath.Dir(dir), 0o755)
			if b, err := run("git", "clone", "-q", "--depth", "1", r.URL, dir); err != nil {
				results = append(results, repoResult{Name: r.Name, ScanErr: "clone: " + string(b)})
				continue
			}
		}
		target := filepath.Join(dir, r.Path)
		// A previous scan leaves .vulnetix/sbom.cdx.json behind, and a scan carries the
		// components its findings reference over from it. Left in place, components from
		// an earlier build of the tool (a Gemfile range read as a version) would be
		// measured as if this build had produced them.
		_ = os.RemoveAll(filepath.Join(target, ".vulnetix"))
		outFile := filepath.Join(*work, r.Name+".report.json")
		_ = os.Remove(outFile)
		depth := r.Depth
		if depth == 0 {
			depth = 3
		}
		b, err := run(*bin, "scan", "--only", "sca", "--no-malscan", "--no-aibom", "--no-cbom", "--disable-memory",
			"--no-progress", "--path", target, "--depth", fmt.Sprint(depth), "-o", outFile)
		_ = b
		raw, rerr := os.ReadFile(outFile)
		if rerr != nil {
			results = append(results, repoResult{Name: r.Name, ScanErr: fmt.Sprintf("scan produced no report (%v): %.300s", err, b)})
			continue
		}
		var rep vxReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			results = append(results, repoResult{Name: r.Name, ScanErr: "bad report: " + err.Error()})
			continue
		}
		res := compare(r.Name, &rep, bomPurls(filepath.Join(target, ".vulnetix", "sbom.cdx.json")), osv)
		results = append(results, res)
		fmt.Fprintf(os.Stderr, "%-18s pkgs=%-4d counted=%-4d matched=%-4d FP=%-3d FN=%-3d ruledOutByUs=%-3d unverified=%d\n",
			r.Name, res.Packages, res.Counted, res.Matched, res.FP, res.FN, res.OSVRulesOut, res.UnverifiedAdvisories)
	}

	classes, recall := report(results, *maxShow)
	failed := false
	if *maxWrong >= 0 && classes["FP-REAL"] > *maxWrong {
		fmt.Printf("\nFAIL: %d wrong \"affected\" claims (limit %d)\n", classes["FP-REAL"], *maxWrong)
		failed = true
	}
	if *minRecall > 0 && recall >= 0 && recall < *minRecall {
		fmt.Printf("\nFAIL: recall %.1f%% is below %.1f%%\n", recall, *minRecall)
		failed = true
	}
	if failed {
		os.Exit(1)
	}
	if *out != "" {
		b, _ := json.MarshalIndent(results, "", "  ")
		_ = os.WriteFile(*out, b, 0o644)
	}
}

// report prints the summary and returns the count of findings per class and the
// recall percentage (-1 when OSV listed nothing), for the caller's thresholds.
func report(results []repoResult, maxShow int) (map[string]int, float64) {
	var tot repoResult
	byClass := map[string][]finding{}
	for _, r := range results {
		if r.ScanErr != "" {
			fmt.Printf("\n!! %s: %s\n", r.Name, r.ScanErr)
			continue
		}
		tot.Packages += r.Packages
		tot.Counted += r.Counted
		tot.Matched += r.Matched
		tot.OSVMatched += r.OSVMatched
		tot.Mislabeled += r.Mislabeled
		tot.FP += r.FP
		tot.FN += r.FN
		tot.OSVTotal += r.OSVTotal
		tot.OSVRulesOut += r.OSVRulesOut
		tot.UnverifiedAdvisories += r.UnverifiedAdvisories
		for _, f := range r.Findings {
			byClass[f.Class] = append(byClass[f.Class], f)
		}
		for _, f := range r.Problems {
			byClass[f.Class] = append(byClass[f.Class], f)
		}
	}
	fmt.Printf("\n══ SUMMARY ══\n")
	fmt.Printf("packages %d · advisories counted %d · matched OSV %d · OSV total %d\n", tot.Packages, tot.Counted, tot.Matched, tot.OSVTotal)
	if tot.Counted > 0 {
		fmt.Printf("precision (counted advisories OSV also reports): %.1f%%   (+ %d with the right fix under another id: %.1f%% if those count)\n",
			100*float64(tot.Matched)/float64(tot.Counted), tot.Mislabeled, 100*float64(tot.Matched+tot.Mislabeled)/float64(tot.Counted))
	}
	if tot.OSVTotal > 0 {
		fmt.Printf("recall    (OSV advisories we report):            %.1f%%  (missed %d, ruled out by verdict %d)\n",
			100*float64(tot.OSVMatched)/float64(tot.OSVTotal), tot.FN, tot.OSVRulesOut)
	}
	fmt.Printf("unverified advisories: %d\n", tot.UnverifiedAdvisories)

	classes := make([]string, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	fmt.Printf("\n══ BY CLASS ══\n")
	for _, c := range classes {
		fmt.Printf("%-34s %d\n", c, len(byClass[c]))
	}
	for _, c := range classes {
		fmt.Printf("\n── %s (%d) ──\n", c, len(byClass[c]))
		for i, f := range byClass[c] {
			if i >= maxShow {
				fmt.Printf("   … %d more\n", len(byClass[c])-maxShow)
				break
			}
			fmt.Printf("   %-12s %-48s %-22s %s\n", f.Repo, f.Purl, f.ID, f.Detail)
		}
	}

	counts := map[string]int{}
	for c, fs := range byClass {
		counts[c] = len(fs)
	}
	recall := -1.0
	if tot.OSVTotal > 0 {
		recall = 100 * float64(tot.OSVMatched) / float64(tot.OSVTotal)
	}
	return counts, recall
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "efficacy:", err)
	os.Exit(1)
}

// fixChecks compares the recommended upgrade with what OSV says clears the
// advisories it lists for this exact version. A target below the highest OSV fix
// for the release line the install is on leaves the user vulnerable after doing
// what the tool said.
//
// Only a range that contains the installed version counts: OSV also lists fixes
// for other release lines (a 10.x fix is no use to a 3.x install), and those
// are not what the install needs.
func fixChecks(repo string, p pkg, osvIDs []string, o *osvClient) []finding {
	iv, err := versions.Parse(p.Version)
	if err != nil || len(osvIDs) == 0 {
		return nil
	}
	want := normName(p.Ecosystem, p.Name)
	var maxFixed *versions.Version
	maxID := ""
	for _, id := range osvIDs {
		r := o.vuln(id)
		if r == nil || r.Withdrawn != "" {
			continue
		}
		for _, a := range r.Affected {
			if normName(a.Package.Ecosystem, a.Package.Name) != want {
				continue
			}
			for _, rg := range a.Ranges {
				if rg.Type == "GIT" {
					continue
				}
				var intro *versions.Version
				for _, e := range rg.Events {
					if e.Introduced != "" {
						if e.Introduced == "0" {
							z, _ := versions.Parse("0")
							intro = &z
						} else if v, err := versions.Parse(e.Introduced); err == nil {
							intro = &v
						}
						continue
					}
					if e.Fixed == "" {
						continue
					}
					fv, ferr := versions.Parse(e.Fixed)
					if ferr != nil || intro == nil {
						continue
					}
					if versions.Compare(iv, *intro) >= 0 && versions.Compare(iv, fv) < 0 {
						if maxFixed == nil || versions.Compare(fv, *maxFixed) > 0 {
							v := fv
							maxFixed, maxID = &v, id
						}
					}
				}
			}
		}
	}
	if maxFixed == nil {
		return nil
	}
	var out []finding
	switch {
	case p.Fix.Target == "":
		if p.Fix.State == "none" {
			out = append(out, finding{repo, p.Purl, maxID, "FIX-missing",
				fmt.Sprintf("we say no fix; OSV lists a fix in %s", maxFixed.Original)})
		}
	default:
		tv, terr := versions.Parse(p.Fix.Target)
		if terr == nil && versions.Compare(tv, *maxFixed) < 0 && p.Fix.Of == p.Fix.Clears {
			out = append(out, finding{repo, p.Purl, maxID, "FIX-too-low",
				fmt.Sprintf("we recommend %s; OSV needs %s to clear %s", p.Fix.Target, maxFixed.Original, maxID)})
		}
	}
	return out
}

// fixedMatchesOSV reports whether the advisory's fixed-in version (from its
// range) equals a fixed version in any OSV record for this package.
func fixedMatchesOSV(o *osvClient, a advisory, osvIDs []string, p pkg) bool {
	if a.FixedIn == "" {
		return false
	}
	want, err := versions.Parse(a.FixedIn)
	if err != nil {
		return false
	}
	name := normName(p.Ecosystem, p.Name)
	for _, id := range osvIDs {
		r := o.vuln(id)
		if r == nil {
			continue
		}
		for _, af := range r.Affected {
			if normName(af.Package.Ecosystem, af.Package.Name) != name {
				continue
			}
			for _, rg := range af.Ranges {
				for _, e := range rg.Events {
					if e.Fixed == "" {
						continue
					}
					if fv, err := versions.Parse(e.Fixed); err == nil && versions.Compare(fv, want) == 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

// bomPurls lists the purl of every component in the SBOM the scan wrote.
func bomPurls(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Components []struct {
			Purl string `json:"purl"`
			Type string `json:"type"`
		} `json:"components"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range doc.Components {
		if strings.HasPrefix(c.Purl, "pkg:") && strings.Contains(c.Purl, "@") && !seen[c.Purl] {
			seen[c.Purl] = true
			out = append(out, c.Purl)
		}
	}
	return out
}

func purlDecode(s string) string {
	r := strings.NewReplacer("%40", "@", "%2F", "/", "%3A", ":", "%2f", "/", "%3a", ":", "%2B", "+")
	return r.Replace(s)
}

var gemPlatformPurlRe = regexp.MustCompile(`^(pkg:gem/[^@]+@\d+(?:\.\d+)*(?:\.[A-Za-z0-9]+)*)-(?:x86|x64|arm|aarch|universal|java|jruby|mswin|mingw|darwin|linux|musl|truffle)[A-Za-z0-9_.-]*$`)

// normPlatformPurl drops a precompiled gem's platform from its purl version:
// the scan reports nokogiri 1.19.1, the SBOM lists 1.19.1-x86_64-linux-gnu, and
// they are one release.
func normPlatformPurl(p string) string {
	if m := gemPlatformPurlRe.FindStringSubmatch(p); m != nil {
		return m[1]
	}
	return p
}
