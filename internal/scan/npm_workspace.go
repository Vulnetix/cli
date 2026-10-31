package scan

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// A JavaScript monorepo has one lockfile, at the workspace root. npm, yarn, pnpm
// and bun all install every member from it and write nothing beside a member's
// package.json. A member without a sibling lock is therefore not unlocked: its
// lock is the root's, and the root is the nearest ancestor that declares the
// member as a workspace (package.json "workspaces", lerna.json "packages" or
// pnpm-workspace.yaml "packages") and holds a lockfile (Vulnetix/cli#177).

// NpmWorkspace describes the workspace root that owns a member package.json.
type NpmWorkspace struct {
	RootDir  string // absolute directory of the workspace root
	LockPath string // absolute path of the root's lockfile ("" when it has none)
}

// FindNpmWorkspace returns the workspace root that declares the package.json in
// memberDir as one of its members, searching ancestors nearest first. ok is
// false when no ancestor declares it. A root that declares the member but has no
// lockfile is returned with an empty LockPath: that monorepo is genuinely
// unlocked, and a lockfile further up belongs to some other project.
func FindNpmWorkspace(memberDir string) (NpmWorkspace, bool) {
	memberDir, err := filepath.Abs(memberDir)
	if err != nil {
		return NpmWorkspace{}, false
	}
	for dir := filepath.Dir(memberDir); ; dir = filepath.Dir(dir) {
		patterns := npmWorkspacePatterns(dir)
		if len(patterns) > 0 {
			rel, err := filepath.Rel(dir, memberDir)
			if err == nil && npmWorkspaceIncludes(patterns, filepath.ToSlash(rel)) {
				ws := NpmWorkspace{RootDir: dir}
				for _, name := range npmLockfileNames {
					p := filepath.Join(dir, name)
					if info, err := os.Stat(p); err == nil && !info.IsDir() {
						ws.LockPath = p
						break
					}
				}
				return ws, true
			}
		}
		if parent := filepath.Dir(dir); parent == dir {
			return NpmWorkspace{}, false
		}
	}
}

// npmWorkspacePatterns reads the workspace globs a directory declares: the
// package.json "workspaces" field (an array, or Yarn's {"packages": [...]}) and
// pnpm-workspace.yaml "packages". nil when the directory is not a workspace root.
func npmWorkspacePatterns(dir string) []string {
	var out []string
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		var pj struct {
			Workspaces json.RawMessage `json:"workspaces"`
		}
		if json.Unmarshal(data, &pj) == nil && len(pj.Workspaces) > 0 {
			var list []string
			if json.Unmarshal(pj.Workspaces, &list) != nil {
				var obj struct {
					Packages []string `json:"packages"`
				}
				if json.Unmarshal(pj.Workspaces, &obj) == nil {
					list = obj.Packages
				}
			}
			out = append(out, list...)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "lerna.json")); err == nil {
		// Lerna installs through npm or yarn from one lock at its root; its
		// "packages" globs are the members. VNX-NODE-001 already counts it.
		var lj struct {
			Packages []string `json:"packages"`
		}
		if json.Unmarshal(data, &lj) == nil {
			out = append(out, lj.Packages...)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "pnpm-workspace.yaml")); err == nil {
		var ws struct {
			Packages []string `yaml:"packages"`
		}
		if yaml.Unmarshal(data, &ws) == nil {
			out = append(out, ws.Packages...)
		}
	}
	return out
}

// npmWorkspaceIncludes reports whether a member path (slash-separated, relative
// to the root) is matched by the workspace globs: included by at least one
// pattern and excluded by no "!" pattern. "*" matches one path segment and "**"
// any number, as in npm, yarn, pnpm and bun.
func npmWorkspaceIncludes(patterns []string, rel string) bool {
	if rel == "." || rel == "" || strings.HasPrefix(rel, "../") {
		return false
	}
	included := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		p = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(p), "./"), "/")
		if p == "" {
			continue
		}
		if workspaceGlobMatch(strings.Split(p, "/"), strings.Split(rel, "/")) {
			if neg {
				return false
			}
			included = true
		}
	}
	return included
}

func workspaceGlobMatch(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if workspaceGlobMatch(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if ok, err := path.Match(pat[0], segs[0]); err != nil || !ok {
		return false
	}
	return workspaceGlobMatch(pat[1:], segs[1:])
}

// NpmWorkspaceMemberManifests lists the package.json of every workspace member
// a root declares, in path order. node_modules and dot-directories are not
// searched. nil when rootDir is not a workspace root.
func NpmWorkspaceMemberManifests(rootDir string) []string {
	patterns := npmWorkspacePatterns(rootDir)
	if len(patterns) == 0 {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(rootDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if p != rootDir && (name == "node_modules" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		dir := filepath.Dir(p)
		if rel, err := filepath.Rel(rootDir, dir); err == nil && npmWorkspaceIncludes(patterns, filepath.ToSlash(rel)) {
			out = append(out, p)
		}
		return nil
	})
	return out
}
