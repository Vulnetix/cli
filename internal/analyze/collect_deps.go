package analyze

// The dependency collector, and the cross-repo edges.
//
// This is where a single-repo scan becomes an org graph. The scanner never reads another
// repository. It writes down what this repo *consumes* (every dependency, as a PURL) and what
// it *provides* (its own module identity, as a PURL), and the server forms an edge wherever
// one repo's consumes meets another repo's provides on the same key.
//
// The normalisation is the whole game. Two repositories that spell the same dependency
// differently will never meet, so the join key is always a PURL — not a manifest string, not
// a display name. GitNexus reached the same conclusion from the other direction: its bridge
// joins on a symbol uid, and everything else it tried produced false edges.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/scan"
)

type depStats struct {
	deps []*DependencyRecord

	// What this repo publishes about itself. A repo that declares a module path is claiming to
	// be that package, and any repo depending on it will match here.
	provides []CrossRepoEdge
}

func collectDeps(b *Builder, root string, opts Options) (*depStats, error) {
	st := &depStats{}
	seen := map[string]bool{}
	depIDs := map[string]string{}

	files, err := scan.WalkForScanFiles(scan.WalkOptions{RootPath: root, MaxDepth: 20})
	if err != nil {
		return nil, fmt.Errorf("walk manifests: %w", err)
	}

	for _, f := range files {
		if f.ManifestInfo == nil {
			continue
		}
		rel := strings.TrimPrefix(f.RelPath, "./")
		if rel == "" {
			if r, rerr := filepath.Rel(root, f.Path); rerr == nil {
				rel = filepath.ToSlash(r)
			}
		}
		if rel == "" {
			rel = filepath.ToSlash(filepath.Base(f.Path))
		}

		if scan.SupportedManifestTypes[f.ManifestInfo.Type] {
			pkgs, perr := scan.ParseManifestWithScope(f.Path, f.ManifestInfo.Type)
			if perr == nil {
				for _, pkg := range pkgs {
					purl := cdx.BuildLocalPurl(pkg.Name, pkg.Version, pkg.Ecosystem)
					if purl == "" || seen[purl] {
						continue
					}
					seen[purl] = true
					scope := dependencyScope(pkg)
					sourceType := pkg.SourceType
					discoveredVia := dependencyDiscoveredVia(sourceType, f.ManifestInfo.IsLock)
					st.deps = append(st.deps, &DependencyRecord{
						ID:              uniqueRecordID("dep-", purl, depIDs),
						Type:            "dependency",
						Purl:            purl,
						Ecosystem:       pkg.Ecosystem,
						ManifestPath:    rel,
						Scope:           scope,
						DiscoveredVia:   discoveredVia,
						DeclaredVersion: firstNonEmpty(pkg.VersionSpec, pkg.Version),
						ResolvedVersion: pkg.Version,
					})
				}
			}
		}

		path := f.Path
		// A go.mod's module line is this repository declaring what it is. That declaration is what
		// another repo's `require` will join against.
		if filepath.Base(path) == "go.mod" {
			if mod := goModulePath(path); mod != "" {
				st.provides = append(st.provides, CrossRepoEdge{
					ID:          "xr-provides-" + safeID(mod),
					LocalNodeID: "package:" + mod,
					JoinKind:    "package",
					JoinKey:     "pkg:golang/" + mod,
					Role:        "provides",
					Confidence:  1,
				})
			}
		}
		if filepath.Base(path) == "package.json" {
			if name, private := npmPackageIdentity(path); name != "" && !private {
				st.provides = append(st.provides, CrossRepoEdge{
					ID:          "xr-provides-" + safeID(name),
					LocalNodeID: "package:" + name,
					JoinKind:    "package",
					JoinKey:     "pkg:npm/" + name,
					Role:        "provides",
					Confidence:  1,
				})
			}
		}
	}

	sort.Slice(st.deps, func(i, j int) bool { return st.deps[i].Purl < st.deps[j].Purl })

	emitDepMetrics(b, st, opts)

	return st, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func dependencyScope(pkg scan.ScopedPackage) string {
	if pkg.IsDirect {
		return "direct"
	}
	switch strings.ToLower(pkg.Scope) {
	case "peer":
		return "peer"
	case "optional":
		return "optional"
	default:
		return "transitive"
	}
}

func dependencyDiscoveredVia(sourceType string, isLock bool) string {
	if sourceType == scan.SourceTypeInstalled {
		return "install-dir"
	}
	if isLock {
		return "lockfile"
	}
	return "manifest"
}

func emitDepMetrics(b *Builder, st *depStats, _ Options) {
	refs := make([]EvidenceRef, 0, len(st.deps))
	direct := []EvidenceRef{}
	byEco := map[string][]EvidenceRef{}

	for _, d := range st.deps {
		r := b.AddRecord(d.ID, d)
		refs = append(refs, r)
		if d.Scope == "direct" {
			direct = append(direct, r)
		}
		byEco[d.Ecosystem] = append(byEco[d.Ecosystem], r)
	}

	b.Count(Metric{
		ID: "business.dependencies.total", Family: "business", Name: "Declared dependencies",
		Definition: "Distinct dependencies declared across every manifest in the repository, deduplicated by package URL.",
	}, refs)

	b.Count(Metric{
		ID: "business.dependencies.direct", Family: "business", Name: "Direct dependencies",
		Definition: "Dependencies declared directly by this repository, as opposed to those pulled in transitively.",
	}, direct)

	ecos := make([]string, 0, len(byEco))
	for e := range byEco {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		b.Count(Metric{
			ID:         "business.dependencies.ecosystem." + safeMetricSegment(e),
			Family:     "business",
			Name:       "Dependencies from " + e,
			Definition: "Declared dependencies in the " + e + " ecosystem.",
		}, byEco[e])
	}

	// Staleness is emitted by enrichDependencies, which needs registry metadata this collector
	// does not have. It runs after this one.
}

func goModulePath(abs string) string {
	f, err := os.Open(abs)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}

	return ""
}

func npmPackageIdentity(abs string) (name string, private bool) {
	body, err := os.ReadFile(abs)
	if err != nil {
		return "", false
	}
	var pkg struct {
		Name    string `json:"name"`
		Private bool   `json:"private"`
	}
	if json.Unmarshal(body, &pkg) != nil {
		return "", false
	}

	return pkg.Name, pkg.Private
}
