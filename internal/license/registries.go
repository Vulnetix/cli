package license

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var registryCache sync.Map // "ecosystem:name:version" → string (license)

// getAuthenticatedGitHubRequest creates an HTTP GET request for the GitHub API,
// adding the Authorization header if a token is available.
func getAuthenticatedGitHubRequest(u string) (*http.Request, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if tok := os.Getenv(key); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
			break
		}
	}
	return req, nil
}

// FetchFromEcosystemRegistry attempts to resolve a license from the package's
// native ecosystem registry for ecosystems not covered by deps.dev.
func FetchFromEcosystemRegistry(pkg PackageLicense) string {
	switch strings.ToLower(pkg.Ecosystem) {
	case "rubygems", "gem":
		return fetchRubyGemsLicense(pkg.PackageName)
	case "hex", "erlang":
		return fetchHexLicense(pkg.PackageName)
	case "pub":
		return fetchPubDevLicense(pkg.PackageName)
	case "cabal", "stack", "hackage":
		return fetchHackageLicense(pkg.PackageName)
	case "cran":
		return fetchCRANLicense(pkg.PackageName)
	case "composer":
		return fetchPackagistLicense(pkg.PackageName)
	case "cocoapods":
		return fetchCocoaPodsLicense(pkg.PackageName)
	case "julia":
		return fetchJuliaLicense(pkg.PackageName)
	case "crystal":
		return fetchCrystalLicense(pkg.PackageName, pkg.GitHubURL, pkg.SourceFile)
	case "opam":
		return fetchOpamLicense(pkg.PackageName, pkg.PackageVersion)
	}
	return ""
}

// ecosystemHandledByRegistry returns true for ecosystems FetchFromEcosystemRegistry handles.
func ecosystemHandledByRegistry(ecosystem string) bool {
	switch strings.ToLower(ecosystem) {
	case "rubygems", "gem", "hex", "erlang", "pub", "cabal", "stack", "hackage", "cran",
		"composer", "cocoapods", "julia", "crystal", "opam":
		return true
	}
	return false
}

// BatchFetchRegistryLicenses resolves licenses for packages whose ecosystems
// have native registry APIs not covered by deps.dev. Modifies slice in place,
// setting LicenseSpdxID and LicenseSource = "registry" for resolved packages.
func BatchFetchRegistryLicenses(packages []PackageLicense, onProgress func(resolved, total int)) {
	var needsResolve []int
	for i, pkg := range packages {
		if pkg.LicenseSpdxID == "UNKNOWN" && ecosystemHandledByRegistry(pkg.Ecosystem) {
			needsResolve = append(needsResolve, i)
		}
	}

	if len(needsResolve) == 0 {
		return
	}

	type dedupKey struct{ name, version, ecosystem string }
	dedupResults := sync.Map{}

	// Build dedup list.
	type dedupItem struct {
		key dedupKey
		pkg PackageLicense
	}
	var items []dedupItem
	seen := map[dedupKey]bool{}
	for _, idx := range needsResolve {
		p := packages[idx]
		k := dedupKey{p.PackageName, p.PackageVersion, p.Ecosystem}
		if !seen[k] {
			seen[k] = true
			items = append(items, dedupItem{k, p})
		}
	}

	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	var resolved int
	var mu sync.Mutex

	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(k dedupKey, p PackageLicense) {
			defer wg.Done()
			defer func() { <-sem }()

			cacheKey := k.ecosystem + ":" + k.name + ":" + k.version
			if cached, ok := registryCache.Load(cacheKey); ok {
				if v := cached.(string); v != "" {
					dedupResults.Store(k, v)
					mu.Lock()
					resolved++
					if onProgress != nil {
						onProgress(resolved, len(items))
					}
					mu.Unlock()
				}
				return
			}

			lic := FetchFromEcosystemRegistry(p)
			registryCache.Store(cacheKey, lic)
			if lic != "" {
				dedupResults.Store(k, lic)
				mu.Lock()
				resolved++
				if onProgress != nil {
					onProgress(resolved, len(items))
				}
				mu.Unlock()
			}
		}(it.key, it.pkg)
	}
	wg.Wait()

	for _, idx := range needsResolve {
		pkg := &packages[idx]
		k := dedupKey{pkg.PackageName, pkg.PackageVersion, pkg.Ecosystem}
		if lic, ok := dedupResults.Load(k); ok {
			pkg.LicenseSpdxID = lic.(string)
			pkg.LicenseSource = "registry"
			ids := ParseSPDXExpression(pkg.LicenseSpdxID)
			if len(ids) > 0 {
				pkg.Record = LookupSPDX(ids[0])
			}
		}
	}
}

// ── RubyGems ──────────────────────────────────────────────────────────────

func fetchRubyGemsLicense(name string) string {
	u := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", url.PathEscape(name))
	resp, err := getHTTPClient().Get(u)
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
		Licenses []string `json:"licenses"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	for _, lic := range data.Licenses {
		if lic != "" {
			return NormalizeSPDX(lic)
		}
	}
	return ""
}

// ── Hex.pm (Elixir + Erlang) ─────────────────────────────────────────────

func fetchHexLicense(name string) string {
	u := fmt.Sprintf("https://hex.pm/api/packages/%s", url.PathEscape(name))
	resp, err := getHTTPClient().Get(u)
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
		Meta struct {
			Licenses []string `json:"licenses"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	for _, lic := range data.Meta.Licenses {
		if lic != "" {
			return NormalizeSPDX(lic)
		}
	}
	return ""
}

// ── pub.dev (Dart) ───────────────────────────────────────────────────────

func fetchPubDevLicense(name string) string {
	u := fmt.Sprintf("https://pub.dev/api/packages/%s", url.PathEscape(name))
	resp, err := getHTTPClient().Get(u)
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

	// pub.dev doesn't expose a license field in the pubspec.
	// Resolve via the repository or homepage URL (usually GitHub).
	var data struct {
		Latest struct {
			Pubspec struct {
				Repository string `json:"repository"`
				Homepage   string `json:"homepage"`
			} `json:"pubspec"`
		} `json:"latest"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	for _, repoURL := range []string{data.Latest.Pubspec.Repository, data.Latest.Pubspec.Homepage} {
		if repoURL == "" {
			continue
		}

		// Check if the URL embeds a subdirectory path
		// e.g. https://github.com/dart-lang/test/tree/master/pkgs/test
		if lic := resolvePubDevRepoURL(name, repoURL); lic != "" {
			return lic
		}
	}
	return ""
}

// resolvePubDevRepoURL resolves a pub.dev repository URL to a license,
// handling monorepo cases where the URL includes a subdirectory path.
func resolvePubDevRepoURL(name, repoURL string) string {
	// Extract owner/repo and optional subdirectory.
	for _, prefix := range []string{"https://github.com/", "http://github.com/"} {
		if !strings.HasPrefix(repoURL, prefix) {
			continue
		}
		path := strings.TrimPrefix(repoURL, prefix)
		parts := strings.SplitN(path, "/", 5)
		if len(parts) < 2 {
			break
		}
		owner, repo := parts[0], parts[1]
		ownerRepo := owner + "/" + repo

		// Check for embedded subdirectory: https://github.com/owner/repo/tree/branch/subdir
		if len(parts) >= 5 && parts[2] == "tree" {
			// parts[3] = branch name, parts[4] = subdir path
			subdir := parts[4]
			// Try license files in the subdirectory.
			for _, licName := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"} {
				rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/HEAD/%s/%s",
					ownerRepo, url.PathEscape(subdir), licName)
				if lic := fetchRawLicenseFile(rawURL); lic != "" {
					return lic
				}
			}
		}

		// No subdirectory in URL: try standard repo-level resolution.
		if lic := resolveRepoLicense(owner, repo); lic != "" {
			return lic
		}

		// Monorepo fallback: try packages/{name}/LICENSE (common Dart convention).
		for _, licName := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"} {
			rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/HEAD/packages/%s/%s",
				ownerRepo, url.PathEscape(name), licName)
			if lic := fetchRawLicenseFile(rawURL); lic != "" {
				return lic
			}
		}
		break
	}
	return resolveSourceRepoLicense(repoURL)
}

// ── Hackage (Haskell cabal + stack) ──────────────────────────────────────

func fetchHackageLicense(name string) string {
	// /package/{name}/{name}.cabal returns the latest cabal file as plain text.
	u := fmt.Sprintf("https://hackage.haskell.org/package/%s/%s.cabal",
		url.PathEscape(name), url.PathEscape(name))
	resp, err := getHTTPClient().Get(u)
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

	return parseCabalLicenseText(string(body))
}

// parseCabalLicenseText extracts the license from cabal file content.
// Used both for local manifest extraction and Hackage API responses.
func parseCabalLicenseText(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		// Match "license:" but not "license-file:".
		if strings.HasPrefix(lower, "license:") {
			val := strings.TrimSpace(trimmed[len("license:"):])
			return normalizeHaskellLicense(val)
		}
	}
	return ""
}

// normalizeHaskellLicense maps Haskell cabal license names to SPDX IDs.
func normalizeHaskellLicense(lic string) string {
	lic = strings.TrimSpace(lic)
	switch strings.ToUpper(lic) {
	case "BSD3", "BSD-3-CLAUSE":
		return "BSD-3-Clause"
	case "BSD2", "BSD-2-CLAUSE":
		return "BSD-2-Clause"
	case "MIT":
		return "MIT"
	case "APACHE-2.0", "APACHE 2.0", "APACHE2":
		return "Apache-2.0"
	case "GPL-2", "GPL-2.0", "GPL-2.0-ONLY":
		return "GPL-2.0-only"
	case "GPL-3", "GPL-3.0", "GPL-3.0-ONLY":
		return "GPL-3.0-only"
	case "GPL-2+":
		return "GPL-2.0-or-later"
	case "GPL-3+":
		return "GPL-3.0-or-later"
	case "LGPL-2", "LGPL-2.0", "LGPL-2.0-ONLY":
		return "LGPL-2.0-only"
	case "LGPL-2.1", "LGPL-2.1-ONLY":
		return "LGPL-2.1-only"
	case "LGPL-2.1+":
		return "LGPL-2.1-or-later"
	case "LGPL-3", "LGPL-3.0", "LGPL-3.0-ONLY":
		return "LGPL-3.0-only"
	case "LGPL-3+":
		return "LGPL-3.0-or-later"
	case "MPL-2.0":
		return "MPL-2.0"
	case "ISC":
		return "ISC"
	case "PUBLICDOMAIN", "PUBLIC-DOMAIN":
		return "CC0-1.0"
	case "OtherLicense", "OTHERLICENSE", "OTHER", "UNLICENSE":
		return "UNKNOWN"
	}
	if lic == "" {
		return ""
	}
	// Try NormalizeSPDX for anything that might already be SPDX-formatted.
	return NormalizeSPDX(lic)
}

// ── CRAN (R) ──────────────────────────────────────────────────────────────

func fetchCRANLicense(name string) string {
	u := fmt.Sprintf("https://cran.r-project.org/web/packages/%s/DESCRIPTION", url.PathEscape(name))
	resp, err := getHTTPClient().Get(u)
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

	return parseCRANDescription(string(body))
}

// parseCRANDescription extracts the license from an R DESCRIPTION file.
func parseCRANDescription(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "License:") {
			val := strings.TrimSpace(line[len("License:"):])
			return normalizeRLicense(val)
		}
	}
	return ""
}

// normalizeRLicense maps common R/CRAN license strings to SPDX IDs.
func normalizeRLicense(lic string) string {
	lic = strings.TrimSpace(lic)
	// Strip trailing "| file LICENSE", "+ file LICENSE", etc.
	for _, suffix := range []string{"| file LICENSE", "+ file LICENSE", "file LICENSE"} {
		if strings.Contains(lic, suffix) {
			lic = strings.TrimSpace(lic[:strings.Index(lic, suffix)])
		}
	}
	lic = strings.TrimSpace(strings.TrimRight(lic, "|+"))

	upper := strings.ToUpper(strings.TrimSpace(lic))
	switch {
	case upper == "MIT":
		return "MIT"
	case upper == "GPL-2", upper == "GPL (= 2)", upper == "GPL (== 2)":
		return "GPL-2.0-only"
	case upper == "GPL-3", upper == "GPL (= 3)", upper == "GPL (== 3)":
		return "GPL-3.0-only"
	case strings.HasPrefix(upper, "GPL (>= 2)"), strings.HasPrefix(upper, "GPL (>= 2.0)"):
		return "GPL-2.0-or-later"
	case strings.HasPrefix(upper, "GPL (>= 3)"), strings.HasPrefix(upper, "GPL (>= 3.0)"):
		return "GPL-3.0-or-later"
	case upper == "LGPL-2", upper == "LGPL-2.0":
		return "LGPL-2.0-only"
	case upper == "LGPL-2.1":
		return "LGPL-2.1-only"
	case strings.HasPrefix(upper, "LGPL (>= 2)"):
		return "LGPL-2.0-or-later"
	case strings.HasPrefix(upper, "LGPL (>= 2.1)"):
		return "LGPL-2.1-or-later"
	case upper == "LGPL-3":
		return "LGPL-3.0-only"
	case strings.HasPrefix(upper, "LGPL (>= 3)"):
		return "LGPL-3.0-or-later"
	case strings.HasPrefix(upper, "APACHE"):
		return "Apache-2.0"
	case upper == "BSD_2_CLAUSE", upper == "BSD 2-CLAUSE", upper == "BSD2":
		return "BSD-2-Clause"
	case upper == "BSD_3_CLAUSE", upper == "BSD 3-CLAUSE", upper == "BSD3":
		return "BSD-3-Clause"
	case upper == "CC0", upper == "CC0-1.0", upper == "CC0 1.0":
		return "CC0-1.0"
	case upper == "MPL-2.0", upper == "MPL 2.0", strings.HasPrefix(upper, "MPL (>= 2)"):
		return "MPL-2.0"
	case upper == "ARTISTIC-2.0", upper == "ARTISTIC2", strings.HasPrefix(upper, "ARTISTIC (>= 2)"):
		return "Artistic-2.0"
	case upper == "EUPL":
		return "EUPL-1.1"
	case upper == "AGPL-3", upper == "AGPL (>= 3)":
		return "AGPL-3.0-only"
	}
	if lic == "" {
		return ""
	}
	return NormalizeSPDX(lic)
}

// ── Packagist (PHP Composer) ──────────────────────────────────────────────

func fetchPackagistLicense(name string) string {
	// name is "vendor/package" format; must contain exactly one slash.
	if !strings.Contains(name, "/") {
		return ""
	}
	u := fmt.Sprintf("https://packagist.org/packages/%s.json", name)
	resp, err := getHTTPClient().Get(u)
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
		Package struct {
			Versions map[string]struct {
				License []string `json:"license"`
			} `json:"versions"`
		} `json:"package"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	// Prefer stable versions: iterate and take the first non-dev license.
	var devLicense string
	for ver, info := range data.Package.Versions {
		if len(info.License) == 0 || info.License[0] == "" {
			continue
		}
		lic := NormalizeSPDX(info.License[0])
		if strings.HasPrefix(ver, "dev-") || strings.HasSuffix(ver, "-dev") {
			if devLicense == "" {
				devLicense = lic
			}
			continue
		}
		return lic
	}
	return devLicense
}

// ── CocoaPods ─────────────────────────────────────────────────────────────

// fetchCocoaPodsLicense resolves a CocoaPods pod license by reading its
// podspec.json from the CocoaPods/Specs GitHub repository. The path is
// derived from the first three hex characters of the MD5 hash of the pod name.
func fetchCocoaPodsLicense(name string) string {
	// Get the latest version from trunk API (version list only — no license).
	trunkURL := fmt.Sprintf("https://trunk.cocoapods.org/api/v1/pods/%s", url.PathEscape(name))
	resp, err := getHTTPClient().Get(trunkURL)
	if err == nil && resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil {
			var trunk struct {
				Versions []struct {
					Name string `json:"name"`
				} `json:"versions"`
			}
			if json.Unmarshal(body, &trunk) == nil && len(trunk.Versions) > 0 {
				// The trunk API returns versions in ascending order; take the last (latest).
				if latest := trunk.Versions[len(trunk.Versions)-1].Name; latest != "" {
					if lic := fetchCocoaPodsSpec(name, latest); lic != "" {
						return lic
					}
				}
			}
		}
	} else if resp != nil {
		resp.Body.Close()
	}

	// Trunk API failed (deprecated/renamed pod). Fall back to listing the
	// CocoaPods/Specs GitHub directory to find available versions.
	return fetchCocoaPodsSpecLatestFromGitHub(name)
}

// fetchCocoaPodsSpecLatestFromGitHub finds the latest available version of a pod
// from the CocoaPods/Specs GitHub directory listing and fetches its spec.
func fetchCocoaPodsSpecLatestFromGitHub(name string) string {
	hash := fmt.Sprintf("%x", md5.Sum([]byte(name)))
	dirURL := fmt.Sprintf("https://api.github.com/repos/CocoaPods/Specs/contents/Specs/%s/%s/%s/%s",
		string(hash[0]), string(hash[1]), string(hash[2]), url.PathEscape(name))

	req, err := getAuthenticatedGitHubRequest(dirURL)
	if err != nil {
		return ""
	}
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

	// Directory listing returns an array of {"name": "version", "type": "dir", ...}
	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &entries); err != nil || len(entries) == 0 {
		return ""
	}

	// Take the last entry as the "latest" version (they're typically sorted).
	latest := ""
	for _, e := range entries {
		if e.Type == "dir" {
			latest = e.Name
		}
	}
	if latest == "" {
		return ""
	}

	return fetchCocoaPodsSpec(name, latest)
}

// fetchCocoaPodsSpec downloads a pod's podspec.json from CocoaPods/Specs on GitHub.
// The path uses the first three lowercase hex chars of MD5(podName).
func fetchCocoaPodsSpec(name, version string) string {
	hash := fmt.Sprintf("%x", md5.Sum([]byte(name)))
	specPath := fmt.Sprintf("Specs/%s/%s/%s/%s/%s/%s.podspec.json",
		string(hash[0]), string(hash[1]), string(hash[2]),
		url.PathEscape(name), url.PathEscape(version), url.PathEscape(name))

	u := "https://raw.githubusercontent.com/CocoaPods/Specs/master/" + specPath
	resp, err := getHTTPClient().Get(u)
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

	// podspec.json has "license": "MIT" or "license": {"type": "MIT", ...}
	var spec struct {
		License json.RawMessage `json:"license"`
	}
	if err := json.Unmarshal(body, &spec); err != nil || spec.License == nil {
		return ""
	}

	// Try string form first.
	var licStr string
	if json.Unmarshal(spec.License, &licStr) == nil && licStr != "" {
		return NormalizeSPDX(licStr)
	}
	// Try object form: {"type": "MIT"}.
	var licObj struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(spec.License, &licObj) == nil && licObj.Type != "" {
		return NormalizeSPDX(licObj.Type)
	}
	return ""
}

// ── Julia (General Registry) ──────────────────────────────────────────────

func fetchJuliaLicense(name string) string {
	if name == "" {
		return ""
	}
	// Julia General registry stores packages in subdirectories by first letter.
	firstLetter := strings.ToUpper(string([]rune(name)[0]))
	u := fmt.Sprintf(
		"https://raw.githubusercontent.com/JuliaRegistries/General/master/%s/%s/Package.toml",
		firstLetter, url.PathEscape(name))

	resp, err := getHTTPClient().Get(u)
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

	// Parse TOML: collect repo and subdir fields.
	repoURL := ""
	subdir := ""
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		for _, key := range []string{"repo", "subdir"} {
			if strings.HasPrefix(trimmed, key) {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) != 2 {
					continue
				}
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, "\"'")
				if key == "repo" {
					repoURL = strings.TrimSuffix(val, ".git")
				} else {
					subdir = val
				}
			}
		}
	}

	if repoURL == "" {
		return ""
	}

	// Extract owner/repo from GitHub URL.
	ownerRepo := ""
	for _, prefix := range []string{"https://github.com/", "http://github.com/"} {
		if strings.HasPrefix(repoURL, prefix) {
			path := strings.TrimPrefix(repoURL, prefix)
			parts := strings.SplitN(path, "/", 3)
			if len(parts) >= 2 {
				ownerRepo = parts[0] + "/" + parts[1]
			}
			break
		}
	}

	if ownerRepo == "" {
		return resolveSourceRepoLicense(repoURL)
	}

	owner, repo, _ := strings.Cut(ownerRepo, "/")

	// If the package lives in a monorepo subdirectory, check that subdirectory's
	// LICENSE file directly (the GitHub API /repos/{owner}/{repo}/license only
	// scans the repo root and won't find LICENSE files in subdirectories).
	if subdir != "" {
		for _, licName := range []string{"LICENSE.md", "LICENSE", "LICENSE.txt", "LICENCE"} {
			rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/HEAD/%s/%s",
				ownerRepo, url.PathEscape(subdir), licName)
			if lic := fetchRawLicenseFile(rawURL); lic != "" {
				return lic
			}
		}
	}

	// Fall back to standard repo-level resolution.
	return resolveRepoLicense(owner, repo)
}

// fetchRawLicenseFile downloads a raw license file and classifies its content.
func fetchRawLicenseFile(rawURL string) string {
	resp, err := getHTTPClient().Get(rawURL)
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
	return ClassifyLicenseText(string(body))
}

// ── Crystal (Shards) ──────────────────────────────────────────────────────

// fetchCrystalLicense resolves a Crystal shard license using the GitHub URL
// stored in the package metadata (parsed from shard.yml/shard.lock), then
// falls back to reading the source file if the URL was not captured.
func fetchCrystalLicense(name, gitHubURL, sourceFile string) string {
	// Primary: use the github: field captured during manifest parsing.
	if gitHubURL != "" {
		parts := strings.SplitN(gitHubURL, "/", 2)
		if len(parts) == 2 {
			return resolveRepoLicense(parts[0], parts[1])
		}
	}

	// Fallback: try reading the shard.yml from the source file's directory.
	if sourceFile == "" {
		return ""
	}
	dir := filepath.Dir(sourceFile)
	shardYML := filepath.Join(dir, "shard.yml")
	data, err := os.ReadFile(shardYML)
	if err != nil {
		data, err = os.ReadFile(sourceFile)
		if err != nil {
			return ""
		}
	}

	ownerRepo := extractCrystalGitHub(name, string(data))
	if ownerRepo == "" {
		return ""
	}
	parts := strings.SplitN(ownerRepo, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return resolveRepoLicense(parts[0], parts[1])
}

// extractCrystalGitHub reads a shard.yml body and finds the github: value
// for the named dependency. Returns "owner/repo" or "".
func extractCrystalGitHub(depName, content string) string {
	inDeps := false
	currentDep := ""

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		// Detect dependency block headers.
		if trimmed == "dependencies:" || trimmed == "development_dependencies:" {
			inDeps = true
			continue
		}
		// Exit dependency block on un-indented non-empty key.
		if inDeps && len(line) > 0 && line[0] != ' ' && line[0] != '\t' && trimmed != "" {
			if strings.HasSuffix(trimmed, ":") {
				currentDep = strings.TrimSuffix(trimmed, ":")
			} else {
				inDeps = false
			}
			continue
		}
		if inDeps && strings.EqualFold(currentDep, depName) {
			if strings.HasPrefix(trimmed, "github:") {
				val := strings.TrimSpace(trimmed[len("github:"):])
				val = strings.Trim(val, "\"'")
				return val
			}
		}
	}
	return ""
}

// ── OCaml (opam repository) ───────────────────────────────────────────────

func fetchOpamLicense(name, version string) string {
	// Query the ocaml/opam-repository on GitHub for the package's opam file.
	// Requires version since the path is packages/{name}/{name}.{version}/opam.
	if version == "" || strings.ContainsAny(version, "><=~^") {
		// Version is a constraint, not an exact version — try a GitHub search instead.
		return fetchOpamLicenseViaGitHubSearch(name)
	}

	packageDir := name + "." + version
	u := fmt.Sprintf(
		"https://raw.githubusercontent.com/ocaml/opam-repository/master/packages/%s/%s/opam",
		url.PathEscape(name), url.PathEscape(packageDir))

	resp, err := getHTTPClient().Get(u)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return fetchOpamLicenseViaGitHubSearch(name)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return parseOpamContent(string(body))
}

// fetchOpamLicenseViaGitHubSearch queries the GitHub API to list versions of
// an opam package and fetches the latest opam file.
func fetchOpamLicenseViaGitHubSearch(name string) string {
	// List subdirectories of packages/{name} to find all available versions.
	apiURL := fmt.Sprintf(
		"https://api.github.com/repos/ocaml/opam-repository/contents/packages/%s",
		url.PathEscape(name))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if pat := findGitHubPAT(); pat != "" {
		req.Header.Set("Authorization", "token "+pat)
	}

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

	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return ""
	}

	// Pick the last (latest) directory entry.
	var latest string
	for _, e := range entries {
		if e.Type == "dir" && strings.HasPrefix(e.Name, name+".") {
			latest = e.Name
		}
	}
	if latest == "" {
		return ""
	}

	u := fmt.Sprintf(
		"https://raw.githubusercontent.com/ocaml/opam-repository/master/packages/%s/%s/opam",
		url.PathEscape(name), url.PathEscape(latest))

	resp2, err := getHTTPClient().Get(u)
	if err != nil || resp2.StatusCode != http.StatusOK {
		if resp2 != nil {
			resp2.Body.Close()
		}
		return ""
	}
	defer resp2.Body.Close()

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		return ""
	}

	return parseOpamContent(string(body2))
}

// parseOpamContent extracts license from opam file content.
func parseOpamContent(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "license:") {
			val := strings.TrimSpace(trimmed[len("license:"):])
			val = strings.Trim(val, "\"'")
			if val != "" {
				return NormalizeSPDX(val)
			}
		}
	}
	return ""
}
