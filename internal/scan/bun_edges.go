package scan

import (
	"os"
	"sort"

	"github.com/Vulnetix/vdb-sca-match/parse"
)

// PopulateBunLockEdges adds the parent → child edges a bun.lock records. Each
// package's dependency names are resolved the way Bun installed them (the
// nearest key up the install path), so an edge points at the copy actually
// used. Edges are keyed by package name, as the other lock readers key them; a
// workspace contributes its declared dependencies under its own name.
func (g *DepGraph) PopulateBunLockEdges(lockFilePath string) error {
	if g == nil {
		return nil
	}
	data, err := os.ReadFile(lockFilePath)
	if err != nil {
		return err
	}
	lock, err := parse.ParseBunLock(data)
	if err != nil {
		return err
	}
	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}
	if g.EdgeRanges == nil {
		g.EdgeRanges = make(map[string]map[string]string)
	}
	add := func(parent, child, rng string) {
		if parent == "" || child == "" || parent == child {
			return
		}
		dup := false
		for _, c := range g.Edges[parent] {
			if c == child {
				dup = true
				break
			}
		}
		if !dup {
			g.Edges[parent] = append(g.Edges[parent], child)
		}
		if rng != "" {
			if g.EdgeRanges[parent] == nil {
				g.EdgeRanges[parent] = make(map[string]string)
			}
			g.EdgeRanges[parent][child] = rng
		}
	}
	walk := func(parentName, parentKey string, maps ...map[string]string) {
		for _, m := range maps {
			names := make([]string, 0, len(m))
			for n := range m {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, dep := range names {
				if child, ok := lock.Resolve(parentKey, dep); ok {
					add(parentName, child.Name, m[dep])
				}
			}
		}
	}
	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := lock.Packages[k]
		if p.Workspace {
			continue
		}
		walk(p.Name, k, p.Dependencies, p.OptionalDependencies, p.PeerDependencies)
	}
	for path, ws := range lock.Workspaces {
		if path == "" || ws.Name == "" {
			continue // the root's declarations are DirectDeps, not an edge from a package
		}
		walk(ws.Name, ws.Name, ws.Dependencies, ws.OptionalDependencies, ws.PeerDependencies, ws.DevDependencies)
	}
	return nil
}
