package license

import (
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
		cmd := exec.Command("gh", "auth", "status")
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		ghCLIAvailable = cmd.Run() == nil
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

	// Generic: if it looks like owner/repo (exactly two segments, no dots).
	parts := strings.SplitN(name, "/", 3)
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" && !strings.Contains(parts[0], ".") {
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
	cmd := exec.Command("gh", "api", fmt.Sprintf("repos/%s/%s", owner, repo), "--jq", ".license.spdx_id")
	out, err := cmd.Output()
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
	cmd := exec.Command("gh", "api", fmt.Sprintf("repos/%s/%s/license", owner, repo), "--jq", ".license.spdx_id")
	out, err := cmd.Output()
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
	cmd := exec.Command("gh", "api", fmt.Sprintf("repos/%s/%s/license", owner, repo), "--jq", ".content")
	out, err := cmd.Output()
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

func ghCLILicenseFileContent(owner, repo string) string {
	for _, name := range licenseFileCandidates {
		cmd := exec.Command("gh", "api", fmt.Sprintf("repos/%s/%s/contents/%s", owner, repo, name), "--jq", ".content")
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		content := strings.TrimSpace(string(out))
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

// ── Strategy 4: Discover license files via directory listing ─────────────

func ghCLIDiscoverLicenseFiles(owner, repo string) string {
	cmd := exec.Command("gh", "api", fmt.Sprintf("repos/%s/%s/contents/", owner, repo),
		"--jq", `[.[] | select(.name | test("(?i)(^licen|^copying)")) | .name] | .[]`)
	out, err := cmd.Output()
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
		cmd2 := exec.Command("gh", "api", fmt.Sprintf("repos/%s/%s/contents/%s", owner, repo, name), "--jq", ".content")
		out2, err := cmd2.Output()
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

	sem := make(chan struct{}, 3)
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

// resolveRepoLicense tries all strategies to find a license for owner/repo.
func resolveRepoLicense(owner, repo string) string {
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
