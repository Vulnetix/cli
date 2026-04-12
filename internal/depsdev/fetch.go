package depsdev

import (
	"strings"
	"sync"

	"github.com/vulnetix/cli/internal/update"
)

// BatchEnrich fetches deps.dev data for a set of packages concurrently.
// It deduplicates by (ecosystem, name, version) and calls the progress function
// after each package is processed.
func (c *Client) BatchEnrich(packages []PackageRef, progress func(done, total int)) []PackageEnrichment {
	// Deduplicate by ecosystem:name:version.
	type dedupKey struct{ eco, name, ver string }
	seen := map[dedupKey]bool{}
	var unique []PackageRef
	for _, p := range packages {
		dk := dedupKey{strings.ToLower(p.Ecosystem), p.Name, p.Version}
		if !seen[dk] {
			seen[dk] = true
			unique = append(unique, p)
		}
	}

	total := len(unique)
	if total == 0 {
		return nil
	}

	results := make([]PackageEnrichment, total)
	sem := make(chan struct{}, c.maxConc)
	var wg sync.WaitGroup
	var doneCount int
	var mu sync.Mutex

	for i, pkg := range unique {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, p PackageRef) {
			defer wg.Done()
			defer func() { <-sem }()

			enrichment := c.enrichOne(p)
			results[idx] = enrichment

			mu.Lock()
			doneCount++
			if progress != nil {
				progress(doneCount, total)
			}
			mu.Unlock()
		}(i, pkg)
	}

	wg.Wait()
	return results
}

// enrichOne collects all deps.dev data for a single package@version.
func (c *Client) enrichOne(p PackageRef) PackageEnrichment {
	result := PackageEnrichment{PackageRef: p}

	system := EcosystemToSystem(p.Ecosystem)
	if system == "" {
		return result
	}

	// 1. Fetch version details (advisories, links, provenance, etc.).
	ver, err := c.FetchVersion(system, p.Name, p.Version)
	if err != nil {
		result.Error = err
		return result
	}
	result.VersionData = ver

	// 2. Fetch package info to determine latest version and outdated status.
	pkg, err := c.FetchPackage(system, p.Name)
	if err == nil && pkg != nil {
		latest := findLatestVersion(pkg)
		if latest != "" {
			result.LatestVersion = latest
			result.IsOutdated, result.VersionsBehind = checkOutdated(p.Version, latest, pkg)
		}
	}

	// 3. Fetch advisories for this version.
	for _, ak := range ver.AdvisoryKeys {
		if ak.ID == "" {
			continue
		}
		adv, err := c.FetchAdvisory(ak.ID)
		if err != nil {
			continue
		}
		result.Advisories = append(result.Advisories, *adv)
	}

	// 4. Fetch project scorecard if we have a related project.
	for _, rp := range ver.RelatedProjects {
		if rp.ProjectKey.ID == "" {
			continue
		}
		proj, err := c.FetchProject(rp.ProjectKey.ID)
		if err != nil {
			continue
		}
		result.Project = proj
		break // use the first project with data
	}

	return result
}

// findLatestVersion returns the default (latest) version string from a PackageResponse.
func findLatestVersion(pkg *PackageResponse) string {
	// First try to find the version marked as default.
	for _, v := range pkg.Versions {
		if v.IsDefault {
			return v.VersionKey.Version
		}
	}
	// Fall back to the last version in the list (deps.dev returns them chronologically).
	if len(pkg.Versions) > 0 {
		return pkg.Versions[len(pkg.Versions)-1].VersionKey.Version
	}
	return ""
}

// checkOutdated determines if the installed version is outdated and how many
// versions behind it is relative to the latest.
func checkOutdated(installed, latest string, pkg *PackageResponse) (bool, int) {
	if installed == latest {
		return false, 0
	}

	iv, errI := update.ParseVersion(strings.TrimPrefix(installed, "v"))
	lv, errL := update.ParseVersion(strings.TrimPrefix(latest, "v"))
	if errI != nil || errL != nil {
		// Can't parse versions — fall back to string comparison.
		if installed != latest {
			return true, countVersionsBehind(installed, pkg)
		}
		return false, 0
	}

	if iv.Compare(lv) < 0 {
		return true, countVersionsBehind(installed, pkg)
	}
	return false, 0
}

// countVersionsBehind counts how many versions were published after the installed version.
func countVersionsBehind(installed string, pkg *PackageResponse) int {
	found := false
	count := 0
	for _, v := range pkg.Versions {
		if v.VersionKey.Version == installed {
			found = true
			continue
		}
		if found {
			count++
		}
	}
	return count
}

// EnrichmentMap converts a slice of PackageEnrichment to a map keyed by "name@version".
func EnrichmentMap(enrichments []PackageEnrichment) map[string]*PackageEnrichment {
	m := make(map[string]*PackageEnrichment, len(enrichments))
	for i := range enrichments {
		e := &enrichments[i]
		key := e.Name + "@" + e.Version
		m[key] = e
	}
	return m
}
