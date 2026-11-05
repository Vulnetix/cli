package sast

// What GitHub code scanning reads from a SARIF file beyond the 2.1.0 schema:
//
//   - rule properties.security-severity, a CVSS-like score as a string, which
//     is what sorts an alert into Critical, High, Medium or Low (without it a
//     result shows only as Error, Warning or Note);
//   - rule properties.tags "security" (which makes it a security alert rather
//     than a code-quality one) and "external/cwe/cwe-N" (the CWE filter);
//   - run automationDetails.id "vulnetix/<kind>/", the category. One category
//     per kind is what keeps a secrets upload from closing every SAST alert;
//   - result partialFingerprints.primaryLocationLineHash (linehash.go), which
//     keeps an alert the same alert when its line moves.
//
// GitHub also rejects a run with more than 25,000 results, so PrepareForGitHub
// keeps the worst 25,000.

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// MaxGitHubResultsPerRun is code scanning's per-run result limit.
const MaxGitHubResultsPerRun = 25000

// SecuritySeverity maps a Vulnetix severity to GitHub's security-severity
// score: over 9.0 is Critical, 7.0 to 8.9 High, 4.0 to 6.9 Medium and 0.1 to
// 3.9 Low. Informational findings get no score.
func SecuritySeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low":
		return "2.0"
	}
	return ""
}

// SecurityTags returns tags with "security" and one "external/cwe/cwe-N" per
// CWE added, without duplicates, keeping the existing order first.
func SecurityTags(tags []string, cwes []int) []string {
	out := make([]string, 0, len(tags)+1+len(cwes))
	seen := map[string]bool{}
	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, t := range tags {
		add(t)
	}
	add("security")
	for _, c := range cwes {
		if c > 0 {
			add("external/cwe/cwe-" + strconv.Itoa(c))
		}
	}
	return out
}

// CategoryKind maps a rule kind to its code scanning category name: the rule
// engine calls container rules "oci", which users know as containers.
func CategoryKind(kind string) string {
	switch kind {
	case "", "sast":
		return "sast"
	case "oci":
		return "containers"
	}
	return kind
}

// AutomationID is the run's code scanning category for a kind.
func AutomationID(kind string) string {
	return "vulnetix/" + CategoryKind(kind) + "/"
}

// ScopedKind is the category kind of one leg of a scoped scan: sast/python.
// Code scanning closes an alert only against a later upload in its category, so
// legs that scan different files need different categories.
func ScopedKind(kind, scope string) string {
	if scope == "" {
		return CategoryKind(kind)
	}
	return CategoryKind(kind) + "/" + scope
}

// SetCategory marks every run of a log as belonging to a category kind.
func SetCategory(l *SARIFLog, kind string) {
	for i := range l.Runs {
		l.Runs[i].AutomationDetails = &SARIFAutomationDetails{ID: AutomationID(kind)}
	}
}

// KindOfRun reports the category kind of a run: its automationDetails id when
// set, else the kind its results carry, else "sast".
func KindOfRun(run *SARIFRun) string {
	if run.AutomationDetails != nil {
		if id := strings.Trim(run.AutomationDetails.ID, "/"); strings.HasPrefix(id, "vulnetix/") {
			return strings.TrimPrefix(id, "vulnetix/")
		}
	}
	for _, r := range run.Results {
		if k, ok := r.Properties["vulnetix/kind"].(string); ok && k != "" {
			return CategoryKind(k)
		}
	}
	return "sast"
}

// SplitByKind returns one log per category kind, each with a single run whose
// automationDetails.id is vulnetix/<kind>/ and whose rules are only those its
// results use. A run that already has one kind passes through. The order is
// the order kinds first appear.
func SplitByKind(log *SARIFLog) map[string]*SARIFLog {
	out := map[string]*SARIFLog{}
	if log == nil {
		return out
	}
	for ri := range log.Runs {
		run := log.Runs[ri]
		runKind := KindOfRun(&run)
		byKind := map[string][]SARIFResult{}
		var order []string
		for _, r := range run.Results {
			k := runKind
			// A result's kind says what it is; a scoped run keeps its category.
			if rk, ok := r.Properties["vulnetix/kind"].(string); ok && rk != "" && !strings.Contains(runKind, "/") {
				k = CategoryKind(rk)
			}
			if _, ok := byKind[k]; !ok {
				order = append(order, k)
			}
			byKind[k] = append(byKind[k], r)
		}
		if len(order) == 0 {
			order = []string{runKind}
		}
		for _, k := range order {
			results := byKind[k]
			used := map[string]bool{}
			for _, r := range results {
				used[r.RuleID] = true
			}
			nr := run
			nr.Results = results
			if nr.Results == nil {
				nr.Results = []SARIFResult{}
			}
			nr.Tool.Driver.Rules = nil
			for _, d := range run.Tool.Driver.Rules {
				if used[d.ID] {
					nr.Tool.Driver.Rules = append(nr.Tool.Driver.Rules, d)
				}
			}
			nr.AutomationDetails = &SARIFAutomationDetails{ID: AutomationID(k)}
			dst, ok := out[k]
			if !ok {
				dst = &SARIFLog{Schema: log.Schema, Version: log.Version}
				out[k] = dst
			}
			dst.Runs = append(dst.Runs, nr)
		}
	}
	// Two runs of one kind in one upload is refused by code scanning; fold
	// them into the first.
	for _, l := range out {
		if len(l.Runs) <= 1 {
			continue
		}
		first := l.Runs[0]
		haveRule := map[string]bool{}
		for _, d := range first.Tool.Driver.Rules {
			haveRule[d.ID] = true
		}
		for _, r := range l.Runs[1:] {
			first.Results = append(first.Results, r.Results...)
			for _, d := range r.Tool.Driver.Rules {
				if !haveRule[d.ID] {
					haveRule[d.ID] = true
					first.Tool.Driver.Rules = append(first.Tool.Driver.Rules, d)
				}
			}
			first.Invocations = append(first.Invocations, r.Invocations...)
		}
		l.Runs = []SARIFRun{first}
	}
	return out
}

// AddLineHashes sets partialFingerprints.primaryLocationLineHash on every
// result that has a file location and no hash yet, reading files relative to
// root. Results whose file cannot be read are left without one, as
// codeql-action leaves them.
func AddLineHashes(log *SARIFLog, root string) {
	if log == nil {
		return
	}
	cache := NewLineHashCache()
	for ri := range log.Runs {
		for i := range log.Runs[ri].Results {
			r := &log.Runs[ri].Results[i]
			if r.PartialFingerprints["primaryLocationLineHash"] != "" || len(r.Locations) == 0 {
				continue
			}
			pl := r.Locations[0].PhysicalLocation
			if pl == nil || pl.ArtifactLocation == nil {
				continue
			}
			path := localPath(root, pl.ArtifactLocation.URI)
			if path == "" {
				continue
			}
			line := 1
			if pl.Region != nil && pl.Region.StartLine > 0 {
				line = pl.Region.StartLine
			}
			if h := cache.Hash(path, line); h != "" {
				if r.PartialFingerprints == nil {
					r.PartialFingerprints = map[string]string{}
				}
				r.PartialFingerprints["primaryLocationLineHash"] = h
			}
		}
	}
}

// localPath resolves a SARIF artifact URI to a file under root, or "" for a
// URI that is not a local file (a purl, an image reference, another scheme).
func localPath(root, uri string) string {
	uri = strings.TrimPrefix(uri, "file://")
	if uri == "" || strings.Contains(uri, "://") || strings.HasPrefix(uri, "pkg:") {
		return ""
	}
	if filepath.IsAbs(uri) {
		return uri
	}
	if root == "" {
		root = "."
	}
	return filepath.Join(root, filepath.FromSlash(uri))
}

// PrepareForGitHub makes a log ready for code scanning: line hashes from the
// files under root, and at most MaxGitHubResultsPerRun results per run, the
// most severe kept. It reports how many results were dropped.
func PrepareForGitHub(log *SARIFLog, root string) int {
	if log == nil {
		return 0
	}
	AddLineHashes(log, root)
	dropped := 0
	for ri := range log.Runs {
		res := log.Runs[ri].Results
		if len(res) <= MaxGitHubResultsPerRun {
			continue
		}
		sort.SliceStable(res, func(i, j int) bool {
			return resultRank(res[i]) > resultRank(res[j])
		})
		dropped += len(res) - MaxGitHubResultsPerRun
		log.Runs[ri].Results = res[:MaxGitHubResultsPerRun]
	}
	return dropped
}

func resultRank(r SARIFResult) int {
	if s, ok := r.Properties["severity"].(string); ok {
		switch strings.ToLower(s) {
		case "critical":
			return 5
		case "high":
			return 4
		case "medium":
			return 3
		case "low":
			return 2
		case "info":
			return 1
		}
	}
	switch r.Level {
	case "error":
		return 4
	case "warning":
		return 3
	case "note":
		return 2
	}
	return 0
}
