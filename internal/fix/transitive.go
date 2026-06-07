package fix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/scan"
)

func resolveTransitive(fc *FixCandidate, groups []scan.ManifestGroup, packages []scan.ScopedPackage) {
	if fc.TargetVer == "" {
		fc.Skipped = true
		if fc.SkipReason == "" {
			fc.SkipReason = "no target version for transitive dependency"
		}
		return
	}
	npmFamily := strings.EqualFold(fc.Ecosystem, "npm")
	for _, g := range groups {
		if g.Graph == nil || !groupContainsFile(g, fc.SourceFile) {
			continue
		}
		paths := allPathsTo(g.Graph, fc.PackageName)
		for _, path := range paths {
			if len(path) < 2 {
				continue
			}
			parent := path[len(path)-2]
			rng := ""
			if g.Graph.EdgeRanges != nil && g.Graph.EdgeRanges[parent] != nil {
				rng = g.Graph.EdgeRanges[parent][fc.PackageName]
			}
			fc.ParentName = parent
			fc.ParentRange = rng
			// (a) parent-update — a Safe-Harbour child already satisfies the
			// parent's declared range, so re-resolving the lockfile is enough.
			if rng != "" && Satisfies(fc.TargetVer, rng) {
				fc.Method = MethodParentUpdate
				fc.Command = npmTransitiveCommand(MethodParentUpdate, parent, "")
				fc.Reason = fmt.Sprintf("%s@%s satisfies %s's declared range %q", fc.PackageName, fc.TargetVer, parent, rng)
				return
			}
			// (b) parent-upgrade — only when the parent is a DIRECT dependency we
			// can edit in place, and (npm) we can pin it to a version whose range
			// admits the safe child. Upgrading a *transitive* parent via the
			// manifest would wrongly promote it to a direct dependency, so those
			// fall through to the deterministic child override below.
			if g.Graph.IsDirect(parent) {
				parentPkg := packageByName(packages, parent, fc.Ecosystem)
				parentTarget := ""
				if npmFamily {
					parentTarget = bestNpmParentVersion(parent, parentPkg.Version, fc.PackageName, fc.TargetVer)
				}
				if parentTarget != "" {
					fc.Method = MethodParentUpgrade
					fc.ParentTarget = parentTarget
					fc.Command = npmTransitiveCommand(MethodParentUpgrade, parent, parentTarget)
					fc.Reason = fmt.Sprintf("upgrade direct dependency %s %s -> %s so its declared %s range admits %s@%s", parent, parentPkg.Version, parentTarget, fc.PackageName, fc.PackageName, fc.TargetVer)
					return
				}
			}
		}
	}
	// (c) deterministic override — pin the vulnerable child to the safe version
	// via the package manager's override mechanism. This is the reliable fix for
	// deep transitive chains with no editable parent path.
	if npmFamily {
		fc.Method = MethodOverride
		fc.Skipped = false
		fc.Reason = fmt.Sprintf("pin %s to %s via a package-manager override (no editable parent path resolved the chain)", fc.PackageName, fc.TargetVer)
		fc.Command = overrideInstallNote
		return
	}
	fc.Skipped = true
	fc.Method = MethodOverride
	if fc.SkipReason == "" {
		fc.SkipReason = "transitive dependency path could not be resolved to an editable parent"
	}
	fc.Command = commandFor(*fc, fc.TargetVer)
}

// overrideInstallNote is a placeholder command for override plans; the real
// install command is set per package-manager during command rewriting.
const overrideInstallNote = "# pin via package-manager override, then install"

func groupContainsFile(g scan.ManifestGroup, file string) bool {
	for _, f := range g.Files {
		if f == file {
			return true
		}
	}
	return false
}

func allPathsTo(g *scan.DepGraph, target string) [][]string {
	var paths [][]string
	for root := range g.DirectDeps {
		walkGraph(g, root, target, map[string]bool{}, []string{root}, &paths)
	}
	if len(paths) == 0 {
		if p := g.FindPath(target); len(p) > 1 {
			paths = append(paths, p)
		}
	}
	return paths
}

func walkGraph(g *scan.DepGraph, cur, target string, seen map[string]bool, path []string, out *[][]string) {
	if seen[cur] {
		return
	}
	seen[cur] = true
	if strings.EqualFold(cur, target) {
		cp := make([]string, len(path))
		copy(cp, path)
		*out = append(*out, cp)
		return
	}
	for _, child := range g.Edges[cur] {
		nextSeen := make(map[string]bool, len(seen))
		for k, v := range seen {
			nextSeen[k] = v
		}
		walkGraph(g, child, target, nextSeen, append(path, child), out)
	}
}

func packageByName(packages []scan.ScopedPackage, name, ecosystem string) scan.ScopedPackage {
	for _, p := range packages {
		if strings.EqualFold(p.Name, name) && strings.EqualFold(p.Ecosystem, ecosystem) {
			return p
		}
	}
	return scan.ScopedPackage{}
}

type npmRegistryPackage struct {
	Versions map[string]npmRegistryVersion `json:"versions"`
}

type npmRegistryVersion struct {
	Dependencies     map[string]string `json:"dependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

func bestNpmParentVersion(parent, currentParentVersion, child, targetChildVersion string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://registry.npmjs.org/"+url.PathEscape(parent), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vulnetix-cli-autofix")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}

	var meta npmRegistryPackage
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return ""
	}
	return bestParentVersionFromNpmMeta(meta, currentParentVersion, child, targetChildVersion)
}

func bestParentVersionFromNpmMeta(meta npmRegistryPackage, currentParentVersion, child, targetChildVersion string) string {
	candidates := make([]string, 0, len(meta.Versions))
	for ver, entry := range meta.Versions {
		if currentParentVersion != "" && !greaterOrEqual(ver, currentParentVersion) {
			continue
		}
		rng := entry.Dependencies[child]
		if rng == "" {
			rng = entry.PeerDependencies[child]
		}
		if rng != "" && Satisfies(targetChildVersion, rng) {
			candidates = append(candidates, ver)
		}
	}
	sorted := sortableVersions(candidates, true)
	if len(sorted) == 0 {
		return ""
	}
	return sorted[0]
}
