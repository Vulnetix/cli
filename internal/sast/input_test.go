package sast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildScanInput_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("# Readme\n"), 0644); err != nil {
		t.Fatal(err)
	}

	input, err := BuildScanInput(tmpDir, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !input.FileSet["main.go"] {
		t.Error("expected main.go in file set")
	}
	if !input.FileSet["README.md"] {
		t.Error("expected README.md in file set")
	}
	if input.ScanRoot != tmpDir {
		t.Errorf("expected scan root %q, got %q", tmpDir, input.ScanRoot)
	}
}

func TestBuildScanInput_SkipsSkipDirs(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpDir, "node_modules", "express"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "node_modules", "express", "index.js"), []byte("// js"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	input, err := BuildScanInput(tmpDir, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if input.FileSet["node_modules/express/index.js"] {
		t.Error("node_modules should be skipped")
	}
	if !input.FileSet["main.go"] {
		t.Error("expected main.go in file set")
	}
}

func TestBuildScanInput_MaxDepth(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpDir, "a", "b", "c", "d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "a", "b", "c", "d", "deep.go"), []byte("package deep\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "a", "shallow.go"), []byte("package shallow\n"), 0644); err != nil {
		t.Fatal(err)
	}

	input, err := BuildScanInput(tmpDir, 2, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !input.FileSet["a/shallow.go"] {
		t.Error("shallow file should be included")
	}
	if input.FileSet["a/b/c/d/deep.go"] {
		t.Error("deep file should be excluded by max depth")
	}
}

func TestBuildScanInput_Excludes(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "test_main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	input, err := BuildScanInput(tmpDir, 10, []string{"test_*.go"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !input.FileSet["main.go"] {
		t.Error("main.go should be included")
	}
	if input.FileSet["test_main.go"] {
		t.Error("test_main.go should be excluded")
	}
}

func TestBuildScanInput_LanguageIndicators(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	input, err := BuildScanInput(tmpDir, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	goDirs := input.DirsByLanguage["go"]
	found := false
	for _, d := range goDirs {
		if d == "." {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected '.' dir for go language, got %v", goDirs)
	}
}

func TestShouldExclude_Basename(t *testing.T) {
	if !shouldExclude("test/foo_test.go", []string{"*_test.go"}) {
		t.Error("should exclude by basename pattern")
	}
	if shouldExclude("main.go", []string{"*_test.go"}) {
		t.Error("should not exclude non-matching file")
	}
}

func TestShouldExclude_PathGlob(t *testing.T) {
	if !shouldExclude("vendor/lib.go", []string{"vendor/*"}) {
		t.Error("should exclude by path glob")
	}
	if shouldExclude("lib/vendor.go", []string{"vendor/*"}) {
		t.Error("should not exclude non-matching path")
	}
}

func TestMatchesIndicator_Exact(t *testing.T) {
	files := map[string]bool{"go.mod": true, "main.go": true}
	if !matchesIndicator(files, "go.mod") {
		t.Error("should match exact filename")
	}
	if matchesIndicator(files, "package.json") {
		t.Error("should not match missing filename")
	}
}

func TestMatchesIndicator_Glob(t *testing.T) {
	files := map[string]bool{"test.csproj": true, "main.go": true}
	if !matchesIndicator(files, "*.csproj") {
		t.Error("should match glob pattern")
	}
	if matchesIndicator(files, "*.sln") {
		t.Error("should not match missing glob pattern")
	}
}

func TestLoadFileContents(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\nfunc main() {}"), 0644); err != nil {
		t.Fatal(err)
	}

	input := &ScanInput{
		FileSet:  map[string]bool{"main.go": true},
		ScanRoot: tmpDir,
	}

	LoadFileContents(input, 1<<20)

	if content, ok := input.FileContents["main.go"]; !ok {
		t.Error("expected main.go content to be loaded")
	} else if content != "package main\nfunc main() {}" {
		t.Errorf("unexpected content: %q", content)
	}
}

func TestLoadFileContents_SkipsBinary(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte("some text\x00with null")
	if err := os.WriteFile(filepath.Join(tmpDir, "binary.txt"), data, 0644); err != nil {
		t.Fatal(err)
	}

	input := &ScanInput{
		FileSet:  map[string]bool{"binary.txt": true},
		ScanRoot: tmpDir,
	}

	LoadFileContents(input, 1<<20)

	if _, ok := input.FileContents["binary.txt"]; ok {
		t.Error("binary file should be skipped")
	}
}

// TestBuildScanInput_ExcludesGitDirectory locks in that git's own metadata
// directory never reaches the rule engine. `vulnetix scan` used to walk it and
// report findings such as VNX-1054 against .git/hooks/*.sample — sample hooks
// that git itself ships, that never execute, and that no user can fix.
func TestBuildScanInput_ExcludesGitDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	gitDir := filepath.Join(tmpDir, ".git", "hooks")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "fsmonitor-watchman.sample"), []byte("#!/usr/bin/perl\n# commented block\n# more\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Both the default walk and the --ignore-git walk must exclude it.
	for _, ignoreGit := range []bool{false, true} {
		input, err := BuildScanInputWithOptions(tmpDir, BuildOptions{MaxDepth: 10, IgnoreGit: ignoreGit})
		if err != nil {
			t.Fatalf("ignoreGit=%v: unexpected error: %v", ignoreGit, err)
		}
		if !input.FileSet["main.go"] {
			t.Errorf("ignoreGit=%v: expected main.go in file set", ignoreGit)
		}
		for p := range input.FileSet {
			if p == ".git" || strings.HasPrefix(p, ".git/") {
				t.Errorf("ignoreGit=%v: .git content leaked into the scan input: %q", ignoreGit, p)
			}
		}
	}
}

// TestBuildScanInput_ExcludesGitFilePointer covers linked worktrees and
// submodule checkouts, where `.git` is a file holding "gitdir: <path>" rather
// than a directory. Nested .git directories (vendored repos, submodule
// checkouts committed into the tree) are pruned at any depth.
func TestBuildScanInput_ExcludesGitFilePointer(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, ".git"), []byte("gitdir: /elsewhere/.git/worktrees/wt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(tmpDir, "vendor-src", "dep")
	if err := os.MkdirAll(filepath.Join(subDir, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, ".git", "hooks", "pre-commit.sample"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "dep.go"), []byte("package dep\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	input, err := BuildScanInputWithOptions(tmpDir, BuildOptions{MaxDepth: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !input.FileSet["vendor-src/dep/dep.go"] {
		t.Error("expected vendor-src/dep/dep.go in file set")
	}
	for p := range input.FileSet {
		if p == ".git" || strings.Contains(p, "/.git/") || strings.HasPrefix(p, ".git/") {
			t.Errorf("git metadata leaked into the scan input: %q", p)
		}
	}
}
