package scan

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Vulnetix/cli#177: in a JavaScript monorepo every member's package.json sits
// without a lockfile, because npm, yarn, pnpm and bun install the whole
// workspace from one lock at the root. Each member was reported as "has no
// lockfile" and dropped from SCA, and bun's lock was not read at all. These
// tests drive the real walker, parser, gate and grouping over the same
// monorepo installed by each package manager (testdata/workspaces/<pm>, written
// by bun 1.4, npm 11, pnpm 11 and yarn 4).

var workspacePMs = []struct{ pm, lock string }{
	{"bun", "bun.lock"},
	{"npm", "package-lock.json"},
	{"pnpm", "pnpm-lock.yaml"},
	{"yarn", "yarn.lock"},
}

func TestWorkspaceMonorepo_EveryPackageManager(t *testing.T) {
	for _, c := range workspacePMs {
		t.Run(c.pm, func(t *testing.T) {
			root, err := filepath.Abs(filepath.Join("testdata", "workspaces", c.pm))
			if err != nil {
				t.Fatal(err)
			}
			files, err := WalkForScanFiles(WalkOptions{RootPath: root, MaxDepth: 4})
			if err != nil {
				t.Fatal(err)
			}
			var rels []string
			for _, f := range files {
				rels = append(rels, filepath.ToSlash(filepath.Clean(f.RelPath)))
			}
			for _, want := range []string{c.lock, "package.json", "packages/app/package.json", "tools/fixed-point/package.json"} {
				if !containsString(rels, want) {
					t.Fatalf("walker did not detect %s (got %v)", want, rels)
				}
			}

			filePackages := map[string][]ScopedPackage{}
			fileEcosystems := map[string]string{}
			for _, f := range files {
				if f.ManifestInfo == nil || f.ManifestInfo.Ecosystem != "npm" {
					continue
				}
				if !f.Supported {
					t.Fatalf("%s detected but not supported", f.RelPath)
				}
				pkgs, err := ParseManifestWithScope(f.Path, f.ManifestInfo.Type)
				if err != nil {
					t.Fatalf("parse %s: %v", f.RelPath, err)
				}
				resolved, drop, gerr := ApplyBuildOrLockGate("npm", f.ManifestInfo.Type, f.Path, f.RelPath, true, pkgs)
				if gerr != nil || drop {
					t.Fatalf("%s: the workspace root's %s must cover it, got err=%v drop=%v", f.RelPath, c.lock, gerr, drop)
				}
				for _, p := range resolved {
					if p.Name == "app" || p.Name == "fixed-point" {
						t.Errorf("%s: workspace member %s@%s would be queried as a registry package", f.RelPath, p.Name, p.Version)
					}
					if p.Version != "" && !IsVersionSpecPinned(p.VersionSpec) {
						t.Errorf("%s: range %s %q kept beside the workspace lock", f.RelPath, p.Name, p.VersionSpec)
					}
				}
				filePackages[f.RelPath] = resolved
				fileEcosystems[f.RelPath] = "npm"
			}

			groups := BuildManifestGroups(filePackages, fileEcosystems)
			PopulateInstalledEdges(groups, root)
			var rootGroup *ManifestGroup
			for i := range groups {
				if groups[i].Dir == "." {
					rootGroup = &groups[i]
				}
			}
			if rootGroup == nil || rootGroup.Graph == nil {
				t.Fatalf("no dependency graph for the workspace root: %+v", groups)
			}
			if n := len(rootGroup.Graph.AllDeps); n < 80 {
				t.Errorf("root graph holds %d packages, want the whole tree (80+)", n)
			}
			var direct []string
			for name := range rootGroup.Graph.DirectDeps {
				direct = append(direct, name)
			}
			sort.Strings(direct)
			if got := strings.Join(direct, ","); got != "axios,chalk,dotenv,express,lodash" {
				t.Errorf("direct = %s, want every member's declared dependencies", got)
			}
			if c.pm == "bun" || c.pm == "npm" {
				// These two record dependency edges in the lock; the tree must be read from it.
				if path := rootGroup.Graph.FindPath("negotiator"); len(path) < 3 {
					t.Errorf("no dependency path to a transitive package from the lock's edges: %v", path)
				}
			}
		})
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFindNpmWorkspace(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		member   string
		wantRoot string // "" means not found
		wantLock string
	}{
		{
			name:   "npm array",
			files:  map[string]string{"package.json": `{"workspaces": ["packages/*"]}`, "package-lock.json": "{}", "packages/a/package.json": "{}"},
			member: "packages/a", wantRoot: ".", wantLock: "package-lock.json",
		},
		{
			name:   "yarn object form",
			files:  map[string]string{"package.json": `{"workspaces": {"packages": ["apps/**"], "nohoist": ["**/x"]}}`, "yarn.lock": "", "apps/web/site/package.json": "{}"},
			member: "apps/web/site", wantRoot: ".", wantLock: "yarn.lock",
		},
		{
			name:   "pnpm-workspace.yaml",
			files:  map[string]string{"package.json": `{}`, "pnpm-workspace.yaml": "packages:\n  - 'tools/*'\n  - '!tools/skip'\n", "pnpm-lock.yaml": "", "tools/a/package.json": "{}"},
			member: "tools/a", wantRoot: ".", wantLock: "pnpm-lock.yaml",
		},
		{
			name:   "bun",
			files:  map[string]string{"package.json": `{"workspaces": ["./tools/fixed-point"]}`, "bun.lock": "{}", "tools/fixed-point/package.json": "{}"},
			member: "tools/fixed-point", wantRoot: ".", wantLock: "bun.lock",
		},
		{
			name:   "lerna.json",
			files:  map[string]string{"package.json": `{}`, "lerna.json": `{"packages": ["modules/*"]}`, "package-lock.json": "{}", "modules/a/package.json": "{}"},
			member: "modules/a", wantRoot: ".", wantLock: "package-lock.json",
		},
		{
			name:   "excluded by a negated glob",
			files:  map[string]string{"package.json": `{}`, "pnpm-workspace.yaml": "packages:\n  - 'tools/*'\n  - '!tools/skip'\n", "pnpm-lock.yaml": "", "tools/skip/package.json": "{}"},
			member: "tools/skip",
		},
		{
			name:   "an ancestor lock that does not list the directory is someone else's",
			files:  map[string]string{"package.json": `{"workspaces": ["packages/*"]}`, "package-lock.json": "{}", "examples/demo/package.json": "{}"},
			member: "examples/demo",
		},
		{
			name:   "an ancestor with no workspaces field",
			files:  map[string]string{"package.json": `{"name": "x"}`, "package-lock.json": "{}", "sub/package.json": "{}"},
			member: "sub",
		},
		{
			name:   "a declaring root without a lock is found, with no lock",
			files:  map[string]string{"package.json": `{"workspaces": ["packages/*"]}`, "packages/a/package.json": "{}"},
			member: "packages/a", wantRoot: ".",
		},
		{
			name:   "the nearest declaring root wins",
			files:  map[string]string{"package.json": `{"workspaces": ["repo/**"]}`, "package-lock.json": "{}", "repo/package.json": `{"workspaces": ["pkgs/*"]}`, "repo/bun.lock": "{}", "repo/pkgs/a/package.json": "{}"},
			member: "repo/pkgs/a", wantRoot: "repo", wantLock: "bun.lock",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeFiles(t, root, c.files)
			ws, ok := FindNpmWorkspace(filepath.Join(root, c.member))
			if c.wantRoot == "" {
				if ok {
					t.Fatalf("found %+v, want none", ws)
				}
				return
			}
			if !ok {
				t.Fatal("workspace root not found")
			}
			if want := filepath.Join(root, c.wantRoot); ws.RootDir != want {
				t.Errorf("root = %s, want %s", ws.RootDir, want)
			}
			wantLock := ""
			if c.wantLock != "" {
				wantLock = filepath.Join(root, c.wantRoot, c.wantLock)
			}
			if ws.LockPath != wantLock {
				t.Errorf("lock = %q, want %q", ws.LockPath, wantLock)
			}
		})
	}
}

func TestNpmWorkspaceIncludes(t *testing.T) {
	cases := []struct {
		patterns []string
		rel      string
		want     bool
	}{
		{[]string{"packages/*"}, "packages/a", true},
		{[]string{"packages/*"}, "packages/a/b", false},
		{[]string{"packages/**"}, "packages/a/b", true},
		{[]string{"**"}, "anything/at/all", true},
		{[]string{"./apps/web/"}, "apps/web", true},
		{[]string{"apps/*-app"}, "apps/web-app", true},
		{[]string{"apps/*-app"}, "apps/lib", false},
		{[]string{"packages/*", "!packages/legacy"}, "packages/legacy", false},
		{[]string{"packages/*"}, ".", false},
		{[]string{"**"}, "../outside", false},
	}
	for _, c := range cases {
		if got := npmWorkspaceIncludes(c.patterns, c.rel); got != c.want {
			t.Errorf("npmWorkspaceIncludes(%v, %q) = %v, want %v", c.patterns, c.rel, got, c.want)
		}
	}
}

func TestNpmWorkspaceMemberManifests(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"package.json":                           `{"workspaces": ["packages/*"]}`,
		"packages/a/package.json":                "{}",
		"packages/b/package.json":                "{}",
		"packages/a/node_modules/x/package.json": "{}",
		"other/package.json":                     "{}",
	})
	got := NpmWorkspaceMemberManifests(root)
	for i := range got {
		got[i], _ = filepath.Rel(root, got[i])
		got[i] = filepath.ToSlash(got[i])
	}
	if strings.Join(got, ",") != "packages/a/package.json,packages/b/package.json" {
		t.Errorf("members = %v", got)
	}
	if NpmWorkspaceMemberManifests(filepath.Join(root, "other")) != nil {
		t.Error("a directory that declares no workspaces has no members")
	}
}

// A member scanned on its own, with the workspace lock outside the scanned path,
// cannot be resolved; the note must say which root to scan, not "generate a lock".
func TestGateWorkspaceLockOutsideTheScan(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"package.json":                   `{"workspaces": ["tools/*"]}`,
		"bun.lock":                       "{}",
		"tools/fixed-point/package.json": `{"dependencies": {"lodash": "^4"}}`,
	})
	manifest := filepath.Join(root, "tools", "fixed-point", "package.json")
	pkgs := []ScopedPackage{{Name: "lodash", Version: "4", VersionSpec: "^4", Ecosystem: "npm"}}

	// Scanned from the member: the lock is outside the scan.
	_, _, err := ApplyBuildOrLockGate("npm", "package.json", manifest, "package.json", true, pkgs)
	if err == nil || !strings.Contains(err.Error(), "member of the workspace at "+root) || !strings.Contains(err.Error(), "bun.lock") {
		t.Fatalf("want a note naming the workspace root and its lock, got %v", err)
	}
	if strings.Contains(err.Error(), "generate a lock file") {
		t.Errorf("a workspace member is not unlocked: %v", err)
	}

	// Scanned from the root: covered, ranges dropped.
	got, drop, err := ApplyBuildOrLockGate("npm", "package.json", manifest, "tools/fixed-point/package.json", true, pkgs)
	if err != nil || drop || len(got) != 0 {
		t.Fatalf("covered by the root lock: got %+v drop=%v err=%v", got, drop, err)
	}
}

// bun.lockb is binary and unread, so it must not count as a lock that will be
// scanned: the manifest would then drop its ranges and nothing would replace them.
func TestBunLockbIsNotAReadableLock(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"package.json": "{}", "bun.lockb": "\x00bun"})
	if NpmLockfilePresent(filepath.Join(dir, "package.json")) {
		t.Error("bun.lockb counted as a readable lockfile")
	}
	writeFiles(t, dir, map[string]string{"bun.lock": "{}"})
	if !NpmLockfilePresent(filepath.Join(dir, "package.json")) {
		t.Error("bun.lock not counted as a lockfile")
	}
	info, ok := DetectManifest("bun.lockb")
	if !ok || SupportedManifestTypes[info.Type] {
		t.Errorf("bun.lockb should be detected and reported unsupported: %+v ok=%v", info, ok)
	}
	if info, ok := DetectManifest("bun.lock"); !ok || !info.IsLock || !SupportedManifestTypes[info.Type] {
		t.Errorf("bun.lock should be a supported lockfile: %+v ok=%v", info, ok)
	}
}

func TestNpmNoLockHintNamesBun(t *testing.T) {
	if h := npmBuildOrLockHint("package.json"); !strings.Contains(h, "bun.lock") || !strings.Contains(h, "bun install") {
		t.Errorf("hint does not mention bun: %s", h)
	}
}

func TestPopulateBunLockEdges(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"bun.lock": `{
  "lockfileVersion": 1,
  "workspaces": {"": {"dependencies": {"a": "^1"}}, "packages/lib": {"name": "lib", "dependencies": {"b": "^1"}}},
  "packages": {
    "a": ["a@1.0.0", "", {"dependencies": {"c": "^2"}}, "sha512-A"],
    "a/c": ["c@2.0.0", "", {}, "sha512-C2"],
    "c": ["c@1.0.0", "", {}, "sha512-C1"],
    "b": ["b@1.0.0", "", {"dependencies": {"c": "^1"}}, "sha512-B"],
    "lib": ["lib@workspace:packages/lib"],
  },
}`})
	g := &DepGraph{DirectDeps: map[string]ScopedPackage{}, AllDeps: map[string]ScopedPackage{}}
	if err := g.PopulateBunLockEdges(filepath.Join(dir, "bun.lock")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(g.Edges["a"], ","); got != "c" {
		t.Errorf("a → %s, want c", got)
	}
	if g.EdgeRanges["a"]["c"] != "^2" {
		t.Errorf("a → c range %q, want ^2", g.EdgeRanges["a"]["c"])
	}
	if got := strings.Join(g.Edges["lib"], ","); got != "b" {
		t.Errorf("workspace lib → %s, want b", got)
	}
	if err := g.PopulateBunLockEdges(filepath.Join(dir, "missing.lock")); err == nil {
		t.Error("want an error for a missing lock")
	}
}
