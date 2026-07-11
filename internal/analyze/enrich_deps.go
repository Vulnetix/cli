package analyze

// Dependency staleness.
//
// `versionsBehind` is not "how many releases exist" — a package pinned to the newest version
// is zero behind even if it has four hundred releases. It is the number of releases published
// *between the version this repository resolved and the version the ecosystem recommends*.
// kospex derives it the same way, and its "non-compliant" rule (more than 2 behind) is the one
// used here.
//
// The data comes from /v2/cli.package-insights, which exists precisely so that asking a
// registry question does not fabricate a security scan: routing this through /v2/cli.sca — the
// only other endpoint that knows the answer — would create a ScannerRun and an
// IngestionSnapshot, and the Scanner Results page would fill up with SCA scans nobody ran.
//
// Without credentials, this is `Unmeasured`. Not zero. "Nothing is stale" is a claim, and we
// have not earned it.

import (
	"fmt"
	"time"
)

// PackageInsight is the subset of the endpoint's response this collector uses.
type PackageInsight struct {
	Purl          string
	PublishedAt   *int64
	LatestVersion string
	// Versions is the ecosystem's release list, newest first.
	Versions []VersionStamp
	// Recommended is the version the ecosystem (or Safe Harbour) says to be on.
	Recommended string
	IsEOL       bool
}

type VersionStamp struct {
	Version     string
	PublishedAt *int64
}

// EnrichFunc fetches registry metadata for a batch of PURLs. Injected rather than called
// directly so the collector can be tested without a network, and so that an unauthenticated
// run degrades to `Unmeasured` at one obvious place instead of failing somewhere deep.
type EnrichFunc func(purls []string) (map[string]PackageInsight, error)

func enrichDependencies(b *Builder, deps *depStats, enrich EnrichFunc, now time.Time) {
	unmeasured := func(reason string) {
		for _, m := range staleMetricsWhenUnavailable() {
			b.Unmeasured(m, reason)
		}
	}

	if deps == nil || len(deps.deps) == 0 {
		unmeasured("No dependencies were found, so there is nothing to check for staleness.")

		return
	}
	if enrich == nil {
		unmeasured("Not authenticated to the Vulnetix API, so registry metadata (publish dates and release ordering) could not be fetched. Dependency staleness is unknown — it is not zero.")

		return
	}

	purls := make([]string, 0, len(deps.deps))
	for _, d := range deps.deps {
		purls = append(purls, d.Purl)
	}

	insights, err := enrich(purls)
	if err != nil {
		unmeasured("Could not fetch registry metadata: " + err.Error() +
			". Dependency staleness is unknown — it is not zero.")

		return
	}

	var (
		stale     []EvidenceRef
		veryStale []EvidenceRef
		eol       []EvidenceRef
		aged      []EvidenceRef
		enriched  int
	)

	for _, d := range deps.deps {
		ins, ok := insights[d.Purl]
		if !ok {
			continue
		}
		enriched++

		if ins.PublishedAt != nil {
			t := time.UnixMilli(*ins.PublishedAt)
			d.PublishedAt = t.UTC().Format(time.RFC3339)
			age := int(now.Sub(t).Seconds())
			if age > 0 {
				d.AgeSeconds = &age
			}
		}
		d.LatestVersion = ins.LatestVersion
		d.EOL = ins.IsEOL

		behind := versionsBehind(ins, d.ResolvedVersion)
		if behind >= 0 {
			d.VersionsBehind = &behind
		}

		// The dependency record already exists in the evidence store — the dependency collector
		// added it. Cite it; do not add it twice. The builder would panic on a duplicate, which is
		// how we know.
		ref := EvidenceRef{Kind: "record", RecordID: d.ID}

		// kospex's n-2 rule: more than two releases behind the recommended version.
		if behind > 2 {
			stale = append(stale, ref)
		}
		if behind > 6 {
			veryStale = append(veryStale, ref)
		}
		if ins.IsEOL {
			eol = append(eol, ref)
		}
		// A year without a release is not automatically abandonment — some libraries are simply
		// finished — but it is worth knowing, and combined with an advisory it is decisive.
		if d.AgeSeconds != nil && *d.AgeSeconds > int((365*24*time.Hour).Seconds()) {
			aged = append(aged, ref)
		}
	}

	b.Count(Metric{
		ID: "business.dependencies.stale", Family: "business", Name: "Stale dependencies",
		Definition: "Dependencies more than 2 releases behind the version the ecosystem recommends. `versionsBehind` counts the releases published between the resolved version and the recommended one — not the total number of releases, so a package pinned to the newest version is zero behind however long its release history is.",
		Classification: &Classification{
			Label:      staleClass(len(stale), enriched),
			Thresholds: "more than 2 releases behind the recommended version",
		},
		References: []Reference{{
			Title: "kospex n-2 compliance rule",
			URL:   "https://github.com/kospex/kospex",
		}},
	}, stale)

	b.Count(Metric{
		ID: "business.dependencies.very_stale", Family: "business", Name: "Badly stale dependencies",
		Definition: "Dependencies more than 6 releases behind the recommended version. At this distance an upgrade is a project, not a bump, which is why it is worth separating.",
	}, veryStale)

	b.Count(Metric{
		ID: "business.dependencies.eol", Family: "business", Name: "End-of-life dependencies",
		Definition: "Dependencies whose version is past its end-of-life date. No further security fixes will be published for them, regardless of what is found.",
	}, eol)

	b.Count(Metric{
		ID: "business.dependencies.aged", Family: "business", Name: "Dependencies not released in over a year",
		Definition: "Dependencies whose resolved version was published more than a year ago. Not automatically a problem — some libraries are finished — but combined with an advisory it means nobody is coming to fix it.",
	}, aged)

	if enriched < len(deps.deps) {
		b.Diagnose(Diagnostic{
			Level: "note", Collector: "dependencies",
			Message: fmt.Sprintf(
				"Registry metadata was returned for %d of %d dependencies. The other %d are absent from the staleness metrics rather than counted as current.",
				enriched, len(deps.deps), len(deps.deps)-enriched),
		})
	}
}

// versionsBehind counts releases published between the resolved version and the recommended
// one. Returns -1 when it cannot be determined — which is not zero, and must not be reported
// as though the package were up to date.
func versionsBehind(ins PackageInsight, resolved string) int {
	if resolved == "" || len(ins.Versions) == 0 {
		return -1
	}

	target := ins.Recommended
	if target == "" {
		target = ins.LatestVersion
	}
	if target == "" {
		return -1
	}

	// Versions arrive newest-first. Walk from the recommended version down to the resolved one
	// and count what sits between them.
	iRec, iRes := -1, -1
	for i, v := range ins.Versions {
		if iRec < 0 && v.Version == target {
			iRec = i
		}
		if iRes < 0 && v.Version == resolved {
			iRes = i
		}
	}
	if iRec < 0 || iRes < 0 {
		return -1
	}
	if iRes <= iRec {
		// The resolved version is at or newer than the recommendation. Nothing to do.
		return 0
	}

	return iRes - iRec
}

func staleClass(stale, total int) string {
	if total == 0 {
		return "unknown"
	}
	switch share := float64(stale) / float64(total); {
	case share == 0:
		return "current"
	case share < 0.2:
		return "minor"
	default:
		return "significant"
	}
}

func staleMetricsWhenUnavailable() []Metric {
	return []Metric{
		{ID: "business.dependencies.stale", Family: "business", Unit: "count",
			Name:       "Stale dependencies",
			Definition: "Dependencies more than 2 releases behind the version the ecosystem recommends."},
		{ID: "business.dependencies.very_stale", Family: "business", Unit: "count",
			Name:       "Badly stale dependencies",
			Definition: "Dependencies more than 6 releases behind the recommended version."},
		{ID: "business.dependencies.eol", Family: "business", Unit: "count",
			Name:       "End-of-life dependencies",
			Definition: "Dependencies whose version is past its end-of-life date."},
		{ID: "business.dependencies.aged", Family: "business", Unit: "count",
			Name:       "Dependencies not released in over a year",
			Definition: "Dependencies whose resolved version was published more than a year ago."},
	}
}
