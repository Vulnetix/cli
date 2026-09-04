package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func touch(t *testing.T, root, rel string) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The bug that motivated moving detection into Go: the shell detector tested
// for the .github/workflows directory, so a repository that had the directory
// and no workflows in it reported CI it did not have.
func TestDetectCapabilities_EmptyWorkflowsDirIsNotCI(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := DetectCapabilities(root, Auth{})
	if got.Repo["gh_workflows"] {
		t.Error("an empty .github/workflows is not a workflow")
	}
	if got.Derived.HasCI {
		t.Error("has_ci should be false with no workflow file")
	}

	touch(t, root, ".github/workflows/ci.yml")

	got = DetectCapabilities(root, Auth{})
	if !got.Repo["gh_workflows"] {
		t.Error("a workflow file should be detected")
	}
	if !got.Derived.HasCI {
		t.Error("has_ci should follow gh_workflows")
	}
}

func TestDetectCapabilities_RepoMarkers(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "go.mod")
	touch(t, root, "Dockerfile")
	touch(t, root, "terraform/main.tf")
	touch(t, root, "src/App.csproj")

	got := DetectCapabilities(root, Auth{})

	for _, key := range []string{"go_mod", "dockerfile", "terraform", "csproj"} {
		if !got.Repo[key] {
			t.Errorf("%s should be detected", key)
		}
	}
	for _, key := range []string{"package_json", "cargo_toml", "pom_xml", "gitlab_ci"} {
		if got.Repo[key] {
			t.Errorf("%s should not be detected", key)
		}
	}

	if !got.Derived.HasContainers {
		t.Error("a Dockerfile means containers")
	}
	if !got.Derived.HasIAC {
		t.Error("a .tf file means IaC")
	}
	if got.Derived.PrimaryPackageManager != "go" {
		t.Errorf("primary package manager = %q, want go", got.Derived.PrimaryPackageManager)
	}
}

// A lockfile is what a project installs from, so it outranks the manifest
// beside it.
func TestDetectCapabilities_LockfileWinsThePrimaryManager(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "package.json")
	touch(t, root, "pnpm-lock.yaml")

	if got := DetectCapabilities(root, Auth{}).Derived.PrimaryPackageManager; got != "pnpm" {
		t.Errorf("primary package manager = %q, want pnpm", got)
	}
}

func TestDeriveCapabilities_AuthStatus(t *testing.T) {
	cases := []struct {
		auth Auth
		want string
	}{
		{Auth{Missing: true}, "unauthenticated"},
		{Auth{Community: true}, "community"},
		{Auth{}, "authenticated"},
	}
	for _, tc := range cases {
		if got := deriveCapabilities(Capabilities{}, tc.auth).AuthStatus; got != tc.want {
			t.Errorf("auth %+v -> %q, want %q", tc.auth, got, tc.want)
		}
	}
}

func TestWriteAndReadCapabilities(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "go.mod")

	caps := DetectCapabilities(root, Auth{Community: true})
	path, err := WriteCapabilities(root, caps)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	// Skills already installed on other machines grep this file with
	// indent-anchored patterns, so the two-space indent is part of the contract.
	if !strings.Contains(body, "\n  go_mod: true") {
		t.Errorf("want a two-space indented go_mod entry:\n%s", body)
	}
	if !strings.HasPrefix(body, "# "+CapabilitiesFile) {
		t.Errorf("want the header comment first:\n%s", body[:min(200, len(body))])
	}

	var back Capabilities
	if err := yaml.Unmarshal(raw, &back); err != nil {
		t.Fatalf("the file we write must be the file we read: %v", err)
	}
	if !back.Repo["go_mod"] || back.Derived.AuthStatus != "community" {
		t.Errorf("round trip lost data: %+v", back.Derived)
	}
}

func TestCapabilitiesFresh(t *testing.T) {
	root := t.TempDir()

	if CapabilitiesFresh(root) {
		t.Error("a repository with no file has no fresh detection")
	}

	caps := DetectCapabilities(root, Auth{})
	if _, err := WriteCapabilities(root, caps); err != nil {
		t.Fatal(err)
	}
	if !CapabilitiesFresh(root) {
		t.Error("a detection written just now is fresh")
	}

	// Age it past the TTL.
	caps.DetectedAt = time.Now().Add(-capabilitiesTTL - time.Minute).UTC().Format(time.RFC3339)
	if _, err := WriteCapabilities(root, caps); err != nil {
		t.Fatal(err)
	}
	if CapabilitiesFresh(root) {
		t.Error("a detection older than the TTL is not fresh")
	}

	// An unreadable detection is not a current one: treating it as fresh would
	// pin the repository to something nobody can see.
	path := filepath.Join(root, filepath.FromSlash(CapabilitiesFile))
	if err := os.WriteFile(path, []byte("{{{ not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if CapabilitiesFresh(root) {
		t.Error("a malformed detection is not fresh")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
