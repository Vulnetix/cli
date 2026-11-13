package license

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// ghCLIAvailable caches whether the `gh` CLI is installed and authenticated.
var (
	ghCLIOnce      sync.Once
	ghCLIAvailable bool
)

func isGHCLIAvailable() bool {
	ghCLIOnce.Do(func() {
		// `gh auth token` answers from gh's own config or keyring; `gh auth
		// status` also checks the token against api.github.com, a second on the
		// critical path of a first scan. A token GitHub no longer accepts makes the
		// gh lookups below fail, and FetchLicenseFromGitHub then falls back to the
		// PAT as it does when gh is unavailable. A gh older than `auth token`
		// (2.17) is asked `auth status` as before.
		run := func(args ...string) bool {
			cmd := exec.Command("gh", args...)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			return cmd.Run() == nil
		}
		ghCLIAvailable = run("auth", "token") || run("auth", "status")
	})
	return ghCLIAvailable
}

// resolveOwnerRepo extracts owner/repo from a package name.
// Handles multiple naming conventions:
//   - "github.com/owner/repo[/subpkg]" (Go modules)
//   - "owner/repo" (GitHub Actions, Terraform providers)
func resolveOwnerRepo(name, ecosystem string) (string, string) {
	// Go modules: github.com/owner/repo/v2/subpkg → owner, repo
	if strings.HasPrefix(name, "github.com/") {
		parts := strings.SplitN(strings.TrimPrefix(name, "github.com/"), "/", 3)
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			return parts[0], parts[1]
		}
		return "", ""
	}

	// GitHub Actions: "actions/checkout", "peaceiris/actions-hugo"
	// Terraform providers: "cloudflare/cloudflare"
	// These ecosystems use owner/repo format directly.
	switch strings.ToLower(ecosystem) {
	case "github-actions", "terraform":
		parts := strings.SplitN(name, "/", 3)
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			return parts[0], parts[1]
		}
	}

	// Generic: if it looks like owner/repo (exactly two segments, no dots). A
	// leading @ is a registry scope (npm @types/node, JSR @std/path), never a
	// GitHub owner, which cannot contain @; asking GitHub about one cost a dozen
	// gh round trips that could only 404.
	parts := strings.SplitN(name, "/", 3)
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" && !strings.Contains(parts[0], ".") && !strings.HasPrefix(parts[0], "@") {
		return parts[0], parts[1]
	}

	return "", ""
}

// validOwner and validRepo are the names GitHub allows. A name that is not one
// cannot be a repository, and asking GitHub about it costs requests that can
// only 404. A scan of this repository asked about 46 such names on every run
// (`$/sbom` from a workflow's `uses: $/sbom`, a glob, "<your" from a template),
// each through the whole lookup chain, in every job of the run.
var (
	validOwner = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	validRepo  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

func validOwnerRepo(owner, repo string) bool {
	return validOwner.MatchString(owner) && validRepo.MatchString(repo) && repo != "." && repo != ".."
}

// ── The lookup chain ─────────────────────────────────────────────────────
//
// Each step runs only when the one before it could not answer, and a step
// that proves the rest cannot answer either ends the chain:
//
//  1. GET repos/{owner}/{repo}: its license.spdx_id. A 404 means the token
//     cannot see the repository, so every later request would 404 too.
//  2. GET repos/{owner}/{repo}/license: GitHub's own licence-file detection,
//     with the file's content to classify when GitHub could not name it.
//  3. GET repos/{owner}/{repo}/contents/: the root listing, and the content of
//     each licence-looking file in it.
//
// The chain used to also fetch eleven fixed file names blindly, every one a
// request and most of them 404s, though the listing in step 3 names the same
// files exactly; and then ran again with GITHUB_TOKEN as a "PAT fallback",
// though gh sends GITHUB_TOKEN itself, so it was the same lookups with the
// same token. A repository GitHub could not name cost about 26 requests, and
// a name that was no repository at all cost the same.

// licenseFileCandidates orders the licence files found in a listing: the
// first that classifies wins, these names first.
var licenseFileCandidates = []string{
	"LICENSE", "LICENSE.txt", "LICENSE.md",
	"LICENCE", "LICENCE.txt", "LICENCE.md",
	"COPYING", "COPYING.txt", "COPYING.md",
	"License", "License.txt",
}

// spdxAnswer is an SPDX id gh printed, or "" when it named none.
func spdxAnswer(out []byte) string {
	id := strings.TrimSpace(string(out))
	if id == "" || id == "null" || id == "NOASSERTION" {
		return ""
	}
	return NormalizeSPDX(id)
}

// lookupRepoLicense tries the chain for owner/repo's licence, with no store.
func lookupRepoLicense(owner, repo string) string {
	out, err := ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s", owner, repo), "--jq", jqSPDX)
	if err != nil {
		return "" // absent, unreadable, or GitHub did not answer: nothing later can
	}
	if lic := spdxAnswer(out); lic != "" {
		return lic
	}

	out, err = ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s/license", owner, repo), "--jq", jqSPDX)
	switch {
	case err == nil:
		if lic := spdxAnswer(out); lic != "" {
			return lic
		}
		if lic := classifyContent(ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s/license", owner, repo), "--jq", jqContent)); lic != "" {
			return lic
		}
	case !isNotFound(err):
		return ""
	}

	return discoverLicenseFiles(owner, repo)
}

// discoverLicenseFiles classifies the licence-looking files in the repository
// root, licenseFileCandidates first.
func discoverLicenseFiles(owner, repo string) string {
	out, err := ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s/contents/", owner, repo), "--jq", jqLicDir)
	if err != nil {
		return ""
	}
	var names []string
	for _, n := range strings.Split(string(out), "\n") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	rank := func(n string) int {
		for i, c := range licenseFileCandidates {
			if n == c {
				return i
			}
		}
		return len(licenseFileCandidates)
	}
	sort.SliceStable(names, func(i, j int) bool { return rank(names[i]) < rank(names[j]) })
	for _, name := range names {
		if githubBudget().Exhausted() {
			return ""
		}
		if lic := classifyContent(ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s/contents/%s", owner, repo, name), "--jq", jqContent)); lic != "" {
			return lic
		}
	}
	return ""
}

// classifyContent classifies the base64 content gh printed for a file.
func classifyContent(out []byte, err error) string {
	if err != nil {
		return ""
	}
	content := strings.TrimSpace(string(out))
	if content == "" || content == "null" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content, "\n", ""))
	if err != nil {
		return ""
	}
	return classifyWithSPDXHeader(string(decoded))
}

// ── classifyWithSPDXHeader checks for SPDX headers then falls back to text classification ──

func classifyWithSPDXHeader(text string) string {
	// Check for SPDX-License-Identifier header (common in Linux kernel, some Go projects).
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SPDX-License-Identifier:") {
			id := strings.TrimSpace(strings.TrimPrefix(trimmed, "SPDX-License-Identifier:"))
			// May contain WITH clause: "GPL-2.0 WITH Linux-syscall-note"
			ids := ParseSPDXExpression(id)
			if len(ids) > 0 {
				return NormalizeSPDX(ids[0])
			}
		}
	}
	// Fall back to full text classification.
	return ClassifyLicenseText(text)
}

func findGitHubPAT() string {
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

// ── Batch resolution ─────────────────────────────────────────────────────

// BatchFetchGitHubLicenses resolves licenses for GitHub-hosted packages concurrently.
// Handles github.com/ prefixed packages (Go), owner/repo packages (GHA, Terraform),
// and any other package that maps to a GitHub repository.
func BatchFetchGitHubLicenses(packages []PackageLicense, onProgress func(resolved, total int)) {
	type job struct {
		idx       int
		ownerRepo string
	}
	var jobs []job

	for i, pkg := range packages {
		if pkg.LicenseSpdxID != "UNKNOWN" && !strings.EqualFold(pkg.LicenseSpdxID, "non-standard") {
			continue
		}
		owner, repo := resolveOwnerRepo(pkg.PackageName, pkg.Ecosystem)
		if !validOwnerRepo(owner, repo) {
			continue
		}
		jobs = append(jobs, job{idx: i, ownerRepo: owner + "/" + repo})
	}

	if len(jobs) == 0 {
		return
	}

	// Deduplicate by owner/repo.
	dedupResults := sync.Map{}
	var dedupKeys []string
	dedupSeen := map[string]bool{}
	for _, j := range jobs {
		if !dedupSeen[j.ownerRepo] {
			dedupSeen[j.ownerRepo] = true
			dedupKeys = append(dedupKeys, j.ownerRepo)
		}
	}

	spentBefore := githubBudget().Spent()
	var notChecked atomic.Int64

	// A lookup is one to four requests, so eight run at once.
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var resolved int
	var mu sync.Mutex

	for _, key := range dedupKeys {
		wg.Add(1)
		sem <- struct{}{}
		go func(ownerRepo string) {
			defer wg.Done()
			defer func() { <-sem }()

			parts := strings.SplitN(ownerRepo, "/", 2)
			lic, checked := resolveRepoLicenseBudgeted(parts[0], parts[1])
			if !checked {
				notChecked.Add(1)
			}

			if lic != "" {
				dedupResults.Store(ownerRepo, lic)
				mu.Lock()
				resolved++
				if onProgress != nil {
					onProgress(resolved, len(dedupKeys))
				}
				mu.Unlock()
			}
		}(key)
	}
	wg.Wait()

	reportGitHubLookups(len(dedupKeys), githubBudget().Spent()-spentBefore, int(notChecked.Load()))

	for _, j := range jobs {
		if lic, ok := dedupResults.Load(j.ownerRepo); ok {
			pkg := &packages[j.idx]
			pkg.LicenseSpdxID = lic.(string)
			pkg.LicenseSource = "github"
			ids := ParseSPDXExpression(pkg.LicenseSpdxID)
			if len(ids) > 0 {
				pkg.Record = LookupSPDX(ids[0])
			}
		}
	}
}

// resolveRepoLicense returns owner/repo's licence, from the licence store when it
// holds an answer: a licence for a week, or a definitive miss (see
// resolveRepoLicenseChecked) for a day. Every GitHub lookup in this package goes
// through it, whichever ecosystem led there.
func resolveRepoLicense(owner, repo string) string {
	lic, _ := resolveRepoLicenseBudgeted(owner, repo)
	return lic
}

// resolveRepoLicenseBudgeted is resolveRepoLicense that also reports whether
// owner/repo was checked: false when the request budget had run out first.
func resolveRepoLicenseBudgeted(owner, repo string) (lic string, checked bool) {
	if !validOwnerRepo(owner, repo) {
		return "", true
	}
	key := owner + "/" + repo
	if lic, ok := loadStoredLicense("github", key); ok {
		return lic, true
	}
	if loadStoredMiss("github", key) {
		return "", true
	}
	primeGitHubBudget()
	if githubBudget().Exhausted() {
		return "", false
	}
	lic, definitiveMiss := resolveRepoLicenseChecked(owner, repo)
	if lic != "" {
		storeLicense("github", key, lic)
	} else if definitiveMiss {
		storeMiss("github", key)
	} else if githubBudget().Exhausted() {
		return "", false // the budget ran out part-way through this one
	}
	return lic, true
}

// ghIndefinite records the repos for which some gh call failed for a reason
// other than the thing not existing (HTTP 404): a timeout, auth, rate limit,
// the budget, or no way to ask at all. A miss for such a repo says nothing
// about the repo and is never stored.
var ghIndefinite sync.Map // "owner/repo" -> true

// errNoGitHub is a request that could not be made: no token and no gh.
var errNoGitHub = errors.New("no GitHub credentials for licence lookups")

// ghAPI runs `gh api args...` for owner/repo and returns its stdout. A 404 is
// returned as ghHTTPError{404}, whichever way the request went.
func ghAPI(owner, repo string, args ...string) ([]byte, error) {
	out, err := ghAPICall(args...)
	if err != nil && !isNotFound(err) {
		ghIndefinite.Store(owner+"/"+repo, true)
	}
	return out, err
}

func ghAPICall(args ...string) ([]byte, error) {
	b := githubBudget()
	if b.Exhausted() {
		return nil, errGitHubBudget
	}
	if len(args) == 3 && args[1] == "--jq" {
		if out, ok, err := ghAPIDirect(args[0], args[2]); ok {
			return out, err
		}
	}
	if !isGHCLIAvailable() {
		return nil, errNoGitHub
	}
	cmd := exec.Command("gh", append([]string{"api"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	b.Spend()
	if err != nil {
		msg := stderr.String()
		switch {
		case strings.Contains(msg, "HTTP 404"):
			return out, ghHTTPError{http.StatusNotFound}
		case strings.Contains(strings.ToLower(msg), "rate limit"):
			b.Refused()
		}
	}
	return out, err
}

// isNotFound reports a 404: the thing asked about does not exist for this token.
func isNotFound(err error) bool {
	var h ghHTTPError
	return errors.As(err, &h) && h.status == http.StatusNotFound
}

// resolveRepoLicenseChecked is resolveRepoLicense with no store, that also
// reports whether a miss is definitive: every request either answered or said
// 404.
func resolveRepoLicenseChecked(owner, repo string) (lic string, definitiveMiss bool) {
	key := owner + "/" + repo
	ghIndefinite.Delete(key)
	lic = lookupRepoLicense(owner, repo)
	if lic != "" {
		return lic, false
	}
	_, indefinite := ghIndefinite.Load(key)
	return "", !indefinite
}
