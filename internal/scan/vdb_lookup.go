package scan

import (
	"context"
	"strings"
	"sync"

	"github.com/vulnetix/cli/internal/vdb"
)

// VulnFinding represents a vulnerability found during a local scan.
type VulnFinding struct {
	CveID          string
	PackageName    string
	PackageVer     string
	Ecosystem      string
	Scope          string
	Severity       string
	Score          float64
	MetricType     string
	VectorString   string
	SourceFile     string
	Source         string // upstream vulnerability source name (empty = vulnetix)
	InCisaKev      bool
	InVulnCheckKev bool
	ExploitCount   int
}

// PackageLookupKey uniquely identifies a package by name and ecosystem.
type PackageLookupKey struct {
	Name      string
	Ecosystem string
}

// LookupVulns queries the VDB API for vulnerabilities affecting the given packages.
// It deduplicates by (name, ecosystem) and runs lookups with bounded concurrency.
// The progress callback is called with (done, total) after each package is processed.
//
// Packages with names shorter than 3 characters are skipped (VDB search minimum).
func LookupVulns(
	ctx context.Context,
	client *vdb.Client,
	packages []ScopedPackage,
	concurrency int,
	progress func(done, total int),
) ([]VulnFinding, error) {
	if concurrency <= 0 {
		concurrency = 5
	}

	// Deduplicate by (name, ecosystem) — avoids redundant API calls when the same
	// package appears in both package.json and yarn.lock, for example.
	uniqueKeys := make(map[PackageLookupKey]bool)
	for _, p := range packages {
		name := strings.TrimSpace(p.Name)
		if len(name) < 3 {
			continue // VDB /packages/search requires at least 3 characters
		}
		uniqueKeys[PackageLookupKey{Name: name, Ecosystem: p.Ecosystem}] = true
	}

	if len(uniqueKeys) == 0 {
		return nil, nil
	}

	keys := make([]PackageLookupKey, 0, len(uniqueKeys))
	for k := range uniqueKeys {
		keys = append(keys, k)
	}

	total := len(keys)
	type indexedResult struct {
		idx   int
		key   PackageLookupKey
		vulns []VulnFinding
	}

	resultsCh := make(chan indexedResult, total)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var doneCount int
	var doneMu sync.Mutex

	for i, key := range keys {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, k PackageLookupKey) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := lookupOnePackage(ctx, client, k)
			resultsCh <- indexedResult{idx: idx, key: k, vulns: vulns}

			doneMu.Lock()
			doneCount++
			if progress != nil {
				progress(doneCount, total)
			}
			doneMu.Unlock()
		}(i, key)
	}

	// Close results channel once all goroutines finish.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results keyed by package.
	vulnsByKey := make(map[PackageLookupKey][]VulnFinding)
	for r := range resultsCh {
		if len(r.vulns) > 0 {
			vulnsByKey[r.key] = r.vulns
		}
	}

	// Attach scope and source-file info from each ScopedPackage.
	// A single package (same name+ecosystem) may appear in multiple files.
	type dedupKey struct {
		CveID      string
		PkgName    string
		SourceFile string
	}
	seen := make(map[dedupKey]bool)
	var allVulns []VulnFinding

	for _, p := range packages {
		lk := PackageLookupKey{Name: p.Name, Ecosystem: p.Ecosystem}
		for _, v := range vulnsByKey[lk] {
			v.Scope = p.Scope
			v.SourceFile = p.SourceFile
			v.PackageVer = p.Version
			dk := dedupKey{v.CveID, v.PackageName, v.SourceFile}
			if !seen[dk] {
				seen[dk] = true
				allVulns = append(allVulns, v)
			}
		}
	}

	return allVulns, nil
}

// lookupOnePackage calls the VDB package search for a single package and extracts findings.
func lookupOnePackage(ctx context.Context, client *vdb.Client, key PackageLookupKey) []VulnFinding {
	resp, err := client.SearchPackages(key.Name, key.Ecosystem, 100, 0)
	if err != nil {
		return nil
	}

	packages, _ := resp["packages"].([]interface{})
	if len(packages) == 0 {
		return nil
	}

	lowerName := strings.ToLower(key.Name)

	for _, p := range packages {
		pkg, ok := p.(map[string]interface{})
		if !ok {
			continue
		}

		// Find the exact matching package by name (VDB returns lowercase names).
		pkgName, _ := pkg["packageName"].(string)
		if strings.ToLower(pkgName) != lowerName {
			continue
		}

		// Extract exploitation signals (shared across all vulns for this package).
		var inCisaKev, inVulnCheckKev bool
		var exploitCount int
		if signals, ok := pkg["exploitationSignals"].(map[string]interface{}); ok {
			inCisaKev, _ = signals["inCisaKev"].(bool)
			inVulnCheckKev, _ = signals["inVulnCheckKev"].(bool)
			if ec, ok := signals["exploitCount"].(float64); ok {
				exploitCount = int(ec)
			}
		}

		vulnList, _ := pkg["vulnerabilities"].([]interface{})
		var findings []VulnFinding
		for _, v := range vulnList {
			vMap, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			f := VulnFinding{
				PackageName:    pkgName,
				Ecosystem:      key.Ecosystem,
				InCisaKev:      inCisaKev,
				InVulnCheckKev: inVulnCheckKev,
				ExploitCount:   exploitCount,
			}
			f.CveID, _ = vMap["cveId"].(string)
			f.Severity, _ = vMap["severity"].(string)
			if score, ok := vMap["score"].(float64); ok {
				f.Score = score
			}
			f.MetricType, _ = vMap["metricType"].(string)
			f.VectorString, _ = vMap["vectorString"].(string)
			f.Source, _ = vMap["source"].(string)

			if f.CveID != "" {
				findings = append(findings, f)
			}
		}
		return findings
	}
	return nil
}
