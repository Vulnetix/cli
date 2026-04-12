package license

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/internal/depsdev"
)

const depsDevMaxConc = 5

var (
	depsDevClientOnce sync.Once
	sharedClient      *depsdev.Client
	depsDevCache      sync.Map // "ecosystem:name:version" → string (license)

	httpClientOnce sync.Once
	httpClient     *http.Client
)

// getHTTPClient returns a shared HTTP client for license-related HTTP calls
// (container metadata, GitHub API, etc.). This is NOT used for deps.dev API calls —
// those go through the shared depsdev.Client.
func getHTTPClient() *http.Client {
	httpClientOnce.Do(func() {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	})
	return httpClient
}

func getSharedClient() *depsdev.Client {
	depsDevClientOnce.Do(func() {
		sharedClient = depsdev.NewClient(depsDevMaxConc)
	})
	return sharedClient
}

// FetchLicenseFromDepsDev queries api.deps.dev for a package's license.
// Returns the SPDX license ID or "" if not found/unsupported.
func FetchLicenseFromDepsDev(name, version, ecosystem string) string {
	system := depsdev.EcosystemToSystem(ecosystem)
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

// fetchVersionLicense calls the shared deps.dev client to get license data.
func fetchVersionLicense(system, name, version string) string {
	resp, err := getSharedClient().FetchVersion(system, name, version)
	if err != nil {
		return ""
	}

	if len(resp.Licenses) > 0 && resp.Licenses[0] != "" {
		lic := resp.Licenses[0]
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
	projectKey := name
	if !strings.HasPrefix(projectKey, "github.com/") {
		return ""
	}

	cacheKey := "project:" + projectKey
	if cached, ok := depsDevCache.Load(cacheKey); ok {
		return cached.(string)
	}

	resp, err := getSharedClient().FetchProject(projectKey)
	if err != nil {
		return ""
	}

	lic := ""
	if resp.License != "" {
		lic = NormalizeSPDX(resp.License)
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
