package license

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	depsDevBaseURL  = "https://api.deps.dev/v3"
	depsDevTimeout = 10 * time.Second
	depsDevMaxConc = 5
)

// depsDevVersionResp is the minimal response from /v3/systems/{eco}/packages/{name}/versions/{ver}.
type depsDevVersionResp struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	Licenses []string `json:"licenses"`
}

// depsDevProjectResp is the minimal response from /v3/projects/{projectKey}.
type depsDevProjectResp struct {
	ProjectKey struct {
		ID string `json:"id"`
	} `json:"projectKey"`
	License string `json:"license"` // SPDX expression
}

var (
	depsDevClient *http.Client
	depsDevOnce   sync.Once
	depsDevCache  sync.Map // "ecosystem:name:version" → string (license)
)

func getHTTPClient() *http.Client {
	depsDevOnce.Do(func() {
		depsDevClient = &http.Client{Timeout: depsDevTimeout}
	})
	return depsDevClient
}

// ecosystemToDepsDevSystem maps internal ecosystem names to deps.dev system names.
func ecosystemToDepsDevSystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "golang", "go":
		return "GO"
	case "npm":
		return "NPM"
	case "pypi":
		return "PYPI"
	case "cargo":
		return "CARGO"
	case "maven":
		return "MAVEN"
	case "nuget":
		return "NUGET"
	default:
		return ""
	}
}

// FetchLicenseFromDepsDev queries api.deps.dev for a package's license.
// Returns the SPDX license ID or "" if not found/unsupported.
func FetchLicenseFromDepsDev(name, version, ecosystem string) string {
	system := ecosystemToDepsDevSystem(ecosystem)
	if system == "" {
		// Unsupported ecosystem — try project endpoint for GitHub repos.
		if isGitHubRepo(name) {
			return fetchProjectLicense(name)
		}
		return ""
	}

	cacheKey := ecosystem + ":" + name + ":" + version
	if cached, ok := depsDevCache.Load(cacheKey); ok {
		return cached.(string)
	}

	// Try version endpoint first.
	lic := fetchVersionLicense(system, name, version)

	// For Go modules, if version lookup fails, try the project endpoint
	// (the module might be a GitHub repo).
	if lic == "" && system == "GO" && isGitHubRepo(name) {
		lic = fetchProjectLicense(name)
	}

	if lic != "" {
		depsDevCache.Store(cacheKey, lic)
	}
	return lic
}

// fetchVersionLicense calls /v3/systems/{system}/packages/{name}/versions/{version}.
func fetchVersionLicense(system, name, version string) string {
	u := fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s",
		depsDevBaseURL,
		url.PathEscape(system),
		url.PathEscape(name),
		url.PathEscape(version))

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

	var data depsDevVersionResp
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	if len(data.Licenses) > 0 && data.Licenses[0] != "" {
		lic := data.Licenses[0]
		// deps.dev returns "non-standard" for custom/unrecognized licenses.
		if strings.EqualFold(lic, "non-standard") {
			return lic // preserve as-is, don't normalize
		}
		return NormalizeSPDX(lic)
	}
	return ""
}

// fetchProjectLicense calls /v3/projects/{projectKey} for GitHub repositories.
func fetchProjectLicense(name string) string {
	// Strip github.com/ prefix if present for the project key.
	projectKey := name
	if !strings.HasPrefix(projectKey, "github.com/") {
		return ""
	}

	cacheKey := "project:" + projectKey
	if cached, ok := depsDevCache.Load(cacheKey); ok {
		return cached.(string)
	}

	u := fmt.Sprintf("%s/projects/%s", depsDevBaseURL, url.PathEscape(projectKey))

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

	var data depsDevProjectResp
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	lic := ""
	if data.License != "" {
		lic = NormalizeSPDX(data.License)
	}
	if lic != "" {
		depsDevCache.Store(cacheKey, lic)
	}
	return lic
}

func isGitHubRepo(name string) bool {
	return strings.HasPrefix(name, "github.com/")
}

// BatchFetchLicenses resolves licenses for multiple packages concurrently via deps.dev.
// It modifies the slice in place, setting LicenseSpdxID and LicenseSource for resolved packages.
func BatchFetchLicenses(packages []PackageLicense, onProgress func(resolved, total int)) {
	// Collect indices of packages needing resolution.
	var needsResolve []int
	for i, pkg := range packages {
		if pkg.LicenseSpdxID == "UNKNOWN" {
			needsResolve = append(needsResolve, i)
		}
	}

	if len(needsResolve) == 0 {
		return
	}

	// Deduplicate by ecosystem:name:version to minimize API calls.
	type lookupKey struct{ name, version, ecosystem string }
	dedupResults := sync.Map{}
	var dedupKeys []lookupKey
	seen := map[lookupKey]bool{}
	for _, idx := range needsResolve {
		pkg := packages[idx]
		key := lookupKey{pkg.PackageName, pkg.PackageVersion, pkg.Ecosystem}
		if !seen[key] {
			seen[key] = true
			dedupKeys = append(dedupKeys, key)
		}
	}

	// Fetch concurrently.
	sem := make(chan struct{}, depsDevMaxConc)
	var wg sync.WaitGroup
	var resolved int
	var mu sync.Mutex

	for _, key := range dedupKeys {
		wg.Add(1)
		sem <- struct{}{}
		go func(k lookupKey) {
			defer wg.Done()
			defer func() { <-sem }()

			lic := FetchLicenseFromDepsDev(k.name, k.version, k.ecosystem)
			if lic != "" {
				dedupResults.Store(k, lic)
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

	// Apply results back to packages.
	for _, idx := range needsResolve {
		pkg := &packages[idx]
		key := lookupKey{pkg.PackageName, pkg.PackageVersion, pkg.Ecosystem}
		if lic, ok := dedupResults.Load(key); ok {
			pkg.LicenseSpdxID = lic.(string)
			pkg.LicenseSource = "deps.dev"
			// Resolve SPDX record.
			ids := ParseSPDXExpression(pkg.LicenseSpdxID)
			if len(ids) > 0 {
				pkg.Record = LookupSPDX(ids[0])
			}
		}
	}
}
