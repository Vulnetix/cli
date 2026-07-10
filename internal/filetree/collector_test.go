package filetree

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollect_NpmEcosystem(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(manifestPath, []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "node_modules", "express"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".gitignore"), []byte("node_modules"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := Collect(manifestPath, tmpDir, "npm")

	if ctx.ManifestRelPath != "package.json" {
		t.Errorf("expected rel path 'package.json', got %q", ctx.ManifestRelPath)
	}
	if ctx.LockfileMap["package.json"] != "package-lock.json" {
		t.Errorf("expected package-lock.json, got %v", ctx.LockfileMap)
	}
	if ctx.GitignoreContent != "node_modules" {
		t.Errorf("expected gitignore content, got %q", ctx.GitignoreContent)
	}
	if len(ctx.NodeModulesTree) < 1 {
		t.Error("expected non-empty node_modules tree")
	}
	if ctx.MonorepoInfo != nil {
		t.Error("expected nil monorepo info for plain npm project")
	}
}

func TestCollect_NoLockfile(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "Cargo.toml")
	if err := os.WriteFile(manifestPath, []byte(`[package]\nname="test"\nversion="0.1.0"`), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := Collect(manifestPath, tmpDir, "rust")

	if len(ctx.LockfileMap) != 0 {
		t.Errorf("expected empty LockfileMap, got %v", ctx.LockfileMap)
	}
}

func TestCollect_NoRepoRoot(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "Gemfile")
	if err := os.WriteFile(manifestPath, []byte("gem 'rails'"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "Gemfile.lock"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := Collect(manifestPath, "", "ruby")

	if ctx.LockfileMap["Gemfile"] != "Gemfile.lock" {
		t.Errorf("expected Gemfile.lock, got %v", ctx.LockfileMap)
	}
}

func TestDetectMonorepo_NpmWorkspaces(t *testing.T) {
	tmpDir := t.TempDir()
	pkgJSON := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(pkgJSON, []byte(`{"workspaces": ["packages/*"]}`), 0644); err != nil {
		t.Fatal(err)
	}

	info := detectMonorepo(tmpDir)
	if info == nil {
		t.Fatal("expected monorepo detection for npm workspaces")
	}
	if !info.IsMonorepo {
		t.Error("expected IsMonorepo true")
	}
	if info.WorkspaceType != "npm-workspaces" {
		t.Errorf("expected npm-workspaces, got %q", info.WorkspaceType)
	}
	if len(info.WorkspacePaths) != 1 || info.WorkspacePaths[0] != "packages/*" {
		t.Errorf("expected workspaces paths [packages/*], got %v", info.WorkspacePaths)
	}
}

func TestDetectMonorepo_NpmWorkspacesMap(t *testing.T) {
	tmpDir := t.TempDir()
	pkgJSON := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(pkgJSON, []byte(`{"workspaces": {"packages": ["apps/*", "libs/*"]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	info := detectMonorepo(tmpDir)
	if info == nil || !info.IsMonorepo || info.WorkspaceType != "npm-workspaces" {
		t.Fatalf("expected npm workspaces monorepo, got %v", info)
	}
}

func TestDetectMonorepo_PnpmWorkspaces(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "pnpm-workspace.yaml"), []byte("packages:"), 0644); err != nil {
		t.Fatal(err)
	}

	info := detectMonorepo(tmpDir)
	if info == nil || !info.IsMonorepo || info.WorkspaceType != "pnpm-workspaces" {
		t.Fatalf("expected pnpm monorepo, got %v", info)
	}
}

func TestDetectMonorepo_Lerna(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "lerna.json"), []byte(`{"packages":["packages/*"]}`), 0644); err != nil {
		t.Fatal(err)
	}

	info := detectMonorepo(tmpDir)
	if info == nil || !info.IsMonorepo || info.WorkspaceType != "lerna" {
		t.Fatalf("expected lerna monorepo, got %v", info)
	}
}

func TestDetectMonorepo_GoWork(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "go.work"), []byte("go 1.21"), 0644); err != nil {
		t.Fatal(err)
	}

	info := detectMonorepo(tmpDir)
	if info == nil || !info.IsMonorepo || info.WorkspaceType != "go-work" {
		t.Fatalf("expected go-work monorepo, got %v", info)
	}
}

func TestDetectMonorepo_CargoWorkspace(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "Cargo.toml"), []byte("[workspace]\nmembers=[\"crate-a\"]"), 0644); err != nil {
		t.Fatal(err)
	}

	info := detectMonorepo(tmpDir)
	if info == nil || !info.IsMonorepo || info.WorkspaceType != "cargo-workspace" {
		t.Fatalf("expected cargo monorepo, got %v", info)
	}
}

func TestDetectMonorepo_None(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("# readme"), 0644); err != nil {
		t.Fatal(err)
	}

	info := detectMonorepo(tmpDir)
	if info != nil {
		t.Errorf("expected nil for no monorepo, got %v", info)
	}
}

func TestReadFileString_Capped(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "large.txt")
	large := make([]byte, 10000)
	for i := range large {
		large[i] = 'x'
	}
	if err := os.WriteFile(path, large, 0644); err != nil {
		t.Fatal(err)
	}

	result := readFileString(path)
	if len(result) > 8192 {
		t.Errorf("expected capped at 8192, got %d", len(result))
	}
}

func TestLockfileAssociations_Coverage(t *testing.T) {
	// Just verify the map has expected keys
	expectedKeys := []string{"package.json", "go.mod", "Cargo.toml", "requirements.txt", "Pipfile", "pyproject.toml", "Gemfile", "composer.json", "pubspec.yaml"}
	for _, key := range expectedKeys {
		if _, ok := lockfileAssociations[key]; !ok {
			t.Errorf("lockfileAssociations missing key %q", key)
		}
	}
}
