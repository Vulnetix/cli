package license

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
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

// FetchLicenseFromGitHub resolves a license for a GitHub-hosted package.
// Uses a multi-strategy approach:
//  1. GitHub repo API .license.spdx_id field (via gh CLI or REST API)
//  2. Dedicated /repos/{owner}/{repo}/license endpoint
//  3. Fetch LICENSE/COPYING file content and classify text
//  4. Discover license files via directory listing
func FetchLicenseFromGitHub(name, ecosystem string) string {
	owner, repo := resolveOwnerRepo(name, ecosystem)
	if owner == "" || repo == "" {
		return ""
	}

	// Strategy 1: repo API .license field.
	if isGHCLIAvailable() {
		if lic := ghCLIRepoLicense(owner, repo); lic != "" {
			return lic
		}
		// Strategy 2: dedicated license endpoint.
		if lic := ghCLIDedicatedLicense(owner, repo); lic != "" {
			return lic
		}
		// Strategy 3: fetch and classify license file content.
		if lic := ghCLILicenseFileContent(owner, repo); lic != "" {
			return lic
		}
		// Strategy 4: discover license files via directory listing.
		if lic := ghCLIDiscoverLicenseFiles(owner, repo); lic != "" {
			return lic
		}
	}

	// Fallback to direct API with PAT.
	if pat := findGitHubPAT(); pat != "" {
		if lic := githubAPILicense(owner, repo, pat); lic != "" {
			return lic
		}
		if lic := githubAPILicenseFileContent(owner, repo, pat); lic != "" {
			return lic
		}
	}

	return ""
}

// ── Strategy 1: Repo API .license field ──────────────────────────────────

func ghCLIRepoLicense(owner, repo string) string {
	out, err := ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s", owner, repo), "--jq", ".license.spdx_id")
	if err != nil {
		return ""
	}
	spdxID := strings.TrimSpace(string(out))
	if spdxID == "" || spdxID == "null" || spdxID == "NOASSERTION" {
		return ""
	}
	return NormalizeSPDX(spdxID)
}

// ── Strategy 2: Dedicated /license endpoint ──────────────────────────────

func ghCLIDedicatedLicense(owner, repo string) string {
	out, err := ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s/license", owner, repo), "--jq", ".license.spdx_id")
	if err != nil {
		return ""
	}
	spdxID := strings.TrimSpace(string(out))
	if spdxID == "" || spdxID == "null" || spdxID == "NOASSERTION" {
		// The /license endpoint also returns content — try classifying it.
		return ghCLIDedicatedLicenseContent(owner, repo)
	}
	return NormalizeSPDX(spdxID)
}

func ghCLIDedicatedLicenseContent(owner, repo string) string {
	out, err := ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s/license", owner, repo), "--jq", ".content")
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

// ── Strategy 3: Fetch known license file names ───────────────────────────

// licenseFileCandidates lists file names to try fetching from the repo root.
var licenseFileCandidates = []string{
	"LICENSE", "LICENSE.txt", "LICENSE.md",
	"LICENCE", "LICENCE.txt", "LICENCE.md",
	"COPYING", "COPYING.txt", "COPYING.md",
	"License", "License.txt",
}

// ghCLILicenseFileContent fetches every candidate at once (each is its own gh
// process and round trip; one after another they took seconds) and returns the
// licence of the first candidate, in list order, that classifies, which is the
// one the sequential loop returned.
func ghCLILicenseFileContent(owner, repo string) string {
	found := make([]string, len(licenseFileCandidates))
	var wg sync.WaitGroup
	for i, name := range licenseFileCandidates {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			found[i] = ghCLIClassifyFile(owner, repo, name)
		}(i, name)
	}
	wg.Wait()
	for _, lic := range found {
		if lic != "" {
			return lic
		}
	}
	return ""
}

// ghCLIClassifyFile returns the licence classified from one repo-root file, or "".
func ghCLIClassifyFile(owner, repo, name string) string {
	out, err := ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s/contents/%s", owner, repo, name), "--jq", ".content")
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

// ── Strategy 4: Discover license files via directory listing ─────────────

func ghCLIDiscoverLicenseFiles(owner, repo string) string {
	out, err := ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s/contents/", owner, repo),
		"--jq", `[.[] | select(.name | test("(?i)(^licen|^copying)")) | .name] | .[]`)
	if err != nil {
		return ""
	}
	names := strings.TrimSpace(string(out))
	if names == "" {
		return ""
	}

	for _, name := range strings.Split(names, "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		// Fetch this specific file's content.
		out2, err := ghAPI(owner, repo, fmt.Sprintf("repos/%s/%s/contents/%s", owner, repo, name), "--jq", ".content")
		if err != nil {
			continue
		}
		content := strings.TrimSpace(string(out2))
		if content == "" || content == "null" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content, "\n", ""))
		if err != nil {
			continue
		}
		if lic := classifyWithSPDXHeader(string(decoded)); lic != "" {
			return lic
		}
	}
	return ""
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

// ── PAT-based fallbacks ──────────────────────────────────────────────────

func findGitHubPAT() string {
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

func githubAPILicense(owner, repo, pat string) string {
	u := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+pat)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := getHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var data struct {
		License *struct {
			SpdxID string `json:"spdx_id"`
		} `json:"license"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.License == nil {
		return ""
	}

	spdxID := data.License.SpdxID
	if spdxID == "" || spdxID == "NOASSERTION" {
		return ""
	}
	return NormalizeSPDX(spdxID)
}

func githubAPILicenseFileContent(owner, repo, pat string) string {
	for _, name := range licenseFileCandidates {
		u := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, name)
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+pat)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		resp, err := getHTTPClient().Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var fileData struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal(body, &fileData); err != nil || fileData.Content == "" {
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(fileData.Content, "\n", ""))
		if err != nil {
			continue
		}

		if lic := classifyWithSPDXHeader(string(decoded)); lic != "" {
			return lic
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
		if owner == "" {
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

	// Each lookup is one or more `gh api` calls (a process and a round trip
	// each), so a project of GitHub-hosted packages waited on them three at a time.
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
			lic := resolveRepoLicense(parts[0], parts[1])

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
	key := owner + "/" + repo
	if lic, ok := loadStoredLicense("github", key); ok {
		return lic
	}
	if loadStoredMiss("github", key) {
		return ""
	}
	lic, definitiveMiss := resolveRepoLicenseChecked(owner, repo)
	if lic != "" {
		storeLicense("github", key, lic)
	} else if definitiveMiss {
		storeMiss("github", key)
	}
	return lic
}

// lookupRepoLicense tries every strategy to find owner/repo's licence, with no store.
func lookupRepoLicense(owner, repo string) string {
	if isGHCLIAvailable() {
		// Strategy 1: repo API.
		if lic := ghCLIRepoLicense(owner, repo); lic != "" {
			return lic
		}
		// Strategy 2: dedicated license endpoint (includes content).
		if lic := ghCLIDedicatedLicense(owner, repo); lic != "" {
			return lic
		}
		// Strategy 3: fetch known license file names.
		if lic := ghCLILicenseFileContent(owner, repo); lic != "" {
			return lic
		}
		// Strategy 4: discover files via directory listing.
		if lic := ghCLIDiscoverLicenseFiles(owner, repo); lic != "" {
			return lic
		}
	}

	if pat := findGitHubPAT(); pat != "" {
		if lic := githubAPILicense(owner, repo, pat); lic != "" {
			return lic
		}
		if lic := githubAPILicenseFileContent(owner, repo, pat); lic != "" {
			return lic
		}
	}

	return ""
}

// ghIndefinite records the repos for which some gh call failed for a reason
// other than the thing not existing (HTTP 404): a timeout, auth, rate limit.
// A miss for such a repo says nothing about the repo and is never stored.
var ghIndefinite sync.Map // "owner/repo" -> true

// ghAPI runs `gh api args...` for owner/repo and returns its stdout.
func ghAPI(owner, repo string, args ...string) ([]byte, error) {
	cmd := exec.Command("gh", append([]string{"api"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && !strings.Contains(stderr.String(), "HTTP 404") {
		ghIndefinite.Store(owner+"/"+repo, true)
	}
	return out, err
}

// resolveRepoLicenseChecked is resolveRepoLicense that also reports whether a
// miss is definitive: every lookup went through gh and each one either answered
// or said 404. A miss through the PAT path, or with gh unavailable, is not.
func resolveRepoLicenseChecked(owner, repo string) (lic string, definitiveMiss bool) {
	key := owner + "/" + repo
	ghIndefinite.Delete(key)
	lic = lookupRepoLicense(owner, repo)
	if lic != "" {
		return lic, false
	}
	_, indefinite := ghIndefinite.Load(key)
	return "", isGHCLIAvailable() && findGitHubPAT() == "" && !indefinite
}
