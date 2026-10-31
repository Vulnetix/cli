package cmd

import (
	"os"
	"path/filepath"
	"testing"

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
