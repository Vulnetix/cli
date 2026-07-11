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

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}

			return nil
		}

		info, ok := scan.DetectManifest(d.Name())
		if !ok || info == nil {
			return nil
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		for _, dep := range parseManifest(path, rel, info) {
			if seen[dep.Purl] {
				continue
			}
			seen[dep.Purl] = true
			st.deps = append(st.deps, dep)
		}

		// A go.mod's module line is this repository declaring what it is. That declaration is what
		// another repo's `require` will join against.
		if d.Name() == "go.mod" {
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
		if d.Name() == "package.json" {
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

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk manifests: %w", err)
	}

	sort.Slice(st.deps, func(i, j int) bool { return st.deps[i].Purl < st.deps[j].Purl })

	emitDepMetrics(b, st, opts)

	return st, nil
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

// ─── manifest parsing ────────────────────────────────────────────────────────────
// Deliberately narrow: only the manifests we can parse *correctly*. A half-parsed lockfile
// produces a dependency list that is wrong in a way nobody notices, which is worse than a
// dependency list that is visibly absent. Anything unparsed is reported in diagnostics.

func parseManifest(abs, rel string, info *scan.ManifestInfo) []*DependencyRecord {
	switch info.Ecosystem {
	case "golang", "go":
		if filepath.Base(rel) == "go.mod" {
			return parseGoMod(abs, rel)
		}
	case "npm":
		if filepath.Base(rel) == "package.json" {
			return parsePackageJSON(abs, rel)
		}
	}

	return nil
}

func parseGoMod(abs, rel string) []*DependencyRecord {
	f, err := os.Open(abs)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []*DependencyRecord
	sc := bufio.NewScanner(f)
	inRequire := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "require ("):
			inRequire = true

			continue
		case inRequire && line == ")":
			inRequire = false

			continue
		}

		var spec string
		if inRequire {
			spec = line
		} else if strings.HasPrefix(line, "require ") {
			spec = strings.TrimPrefix(line, "require ")
		} else {
			continue
		}

		// "// indirect" marks a transitive dependency. Keeping the distinction matters: a direct
		// dependency is a decision somebody made, a transitive one is a consequence.
		scope := "direct"
		if i := strings.Index(spec, "//"); i >= 0 {
			if strings.Contains(spec[i:], "indirect") {
				scope = "transitive"
			}
			spec = strings.TrimSpace(spec[:i])
		}

		parts := strings.Fields(spec)
		if len(parts) < 2 {
			continue
		}
		name, version := parts[0], parts[1]
		purl := "pkg:golang/" + name + "@" + version

		out = append(out, &DependencyRecord{
			ID:              "dep-" + safeID(purl),
			Type:            "dependency",
			Purl:            purl,
			Ecosystem:       "golang",
			ManifestPath:    rel,
			Scope:           scope,
			DiscoveredVia:   "manifest",
			DeclaredVersion: version,
			ResolvedVersion: version,
		})
	}

	return out
}

func parsePackageJSON(abs, rel string) []*DependencyRecord {
	body, err := os.ReadFile(abs)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(body, &pkg) != nil {
		return nil
	}

	var out []*DependencyRecord
	add := func(m map[string]string, scope string) {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			version := m[name]
			purl := "pkg:npm/" + name + "@" + strings.TrimLeft(version, "^~>=< ")
			out = append(out, &DependencyRecord{
				ID:              "dep-" + safeID(purl),
				Type:            "dependency",
				Purl:            purl,
				Ecosystem:       "npm",
				ManifestPath:    rel,
				Scope:           scope,
				DiscoveredVia:   "manifest",
				DeclaredVersion: version,
			})
		}
	}
	add(pkg.Dependencies, "direct")
	add(pkg.DevDependencies, "dev")

	return out
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
