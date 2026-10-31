package cmd

import (
	"os"
	"path/filepath"
	"testing"

	autofix "github.com/vulnetix/cli/v3/internal/fix"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// Every npm-family lockfile names the package manager that installs it, and a
// workspace member (no lockfile of its own) is installed by its root's manager.
// Vulnetix/cli#177: bun.lock was unknown, so a bun monorepo defaulted to
// npm install, which writes a second, competing lockfile.
func TestPackageManagersByDir_EveryLockAndWorkspaceMembers(t *testing.T) {
	for lock, want := range map[string]string{
		"package-lock.json":   "npm",
		"npm-shrinkwrap.json": "npm",
		"yarn.lock":           "yarn",
		"pnpm-lock.yaml":      "pnpm",
		"bun.lock":            "bun",
		"bun.lockb":           "bun",
	} {
		t.Run(lock, func(t *testing.T) {
			root := t.TempDir()
			member := filepath.Join(root, "packages", "app")
			if err := os.MkdirAll(member, 0o755); err != nil {
				t.Fatal(err)
			}
			for p, body := range map[string]string{
				filepath.Join(root, "package.json"):   `{"workspaces": ["packages/*"]}`,
				filepath.Join(root, lock):             "{}",
				filepath.Join(member, "package.json"): `{}`,
			} {
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := packageManagersByDir([]scan.DetectedFile{
				{Path: filepath.Join(root, lock), RelPath: lock},
				{Path: filepath.Join(root, "package.json"), RelPath: "package.json"},
				{Path: filepath.Join(member, "package.json"), RelPath: "packages/app/package.json"},
			})
			if got["."] != want {
				t.Errorf("root: %q, want %q", got["."], want)
			}
			if lock == "bun.lockb" {
				// unread: the gate does not treat it as a lock, and neither does
				// workspace discovery, so the member keeps no manager of its own
				return
			}
			if got["packages/app"] != want {
				t.Errorf("member: %q, want the root's %q", got["packages/app"], want)
			}
		})
	}
}

// A fix left for the user was suggested as "npm install <name>" in every
// project; in a bun, pnpm or yarn project that writes a second lockfile.
func TestNpmCommandForManager_ManualSuggestionUsesTheProjectManager(t *testing.T) {
	manual := autofix.FixCandidate{PackageName: "cookie", Ecosystem: "npm", Command: "npm install cookie"}
	for pm, want := range map[string]string{
		"bun":  "bun add cookie",
		"pnpm": "pnpm add cookie",
		"yarn": "yarn add cookie",
		"npm":  "npm install cookie",
	} {
		if got := npmCommandForManager(manual, pm, false); got != want {
			t.Errorf("%s: %q, want %q", pm, got, want)
		}
	}
	pinned := autofix.FixCandidate{PackageName: "x", Ecosystem: "npm", Command: "npm install x@1.2.3"}
	if got := npmCommandForManager(pinned, "bun", false); got != "bun add x@1.2.3" {
		t.Errorf("pinned manual: %q", got)
	}
}

// In a workspace whose root does not declare the parent, "bun add
// express@4.22.3" at the root made express a new root dependency, though the
// member that declares it had already been bumped. The command is a re-resolve.
func TestRewriteParentUpgradeInAWorkspaceDoesNotAddToTheRoot(t *testing.T) {
	root := t.TempDir()
	member := filepath.Join(root, "packages", "app")
	if err := os.MkdirAll(member, 0o755); err != nil {
		t.Fatal(err)
	}
	for p, body := range map[string]string{
		filepath.Join(root, "package.json"):   `{"workspaces": ["packages/*"], "dependencies": {"dotenv": "^16"}}`,
		filepath.Join(root, "bun.lock"):       "{}",
		filepath.Join(member, "package.json"): `{"dependencies": {"express": "4.17.1"}}`,
	} {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !memberDeclaresParent(filepath.Join(root, "package.json"), "express") {
		t.Fatal("express is declared by a member, not the root")
	}
	if memberDeclaresParent(filepath.Join(root, "package.json"), "dotenv") {
		t.Error("the root declares dotenv itself: add/up at the root is right")
	}
	if memberDeclaresParent(filepath.Join(member, "package.json"), "express") {
		t.Error("a member is not a workspace root")
	}
	if got := npmInstallCommand("bun"); got != "bun install" {
		t.Errorf("npmInstallCommand(bun) = %q", got)
	}
}
