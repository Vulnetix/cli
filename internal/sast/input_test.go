package sast

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildScanInput_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("# Readme\n"), 0644)

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
	os.MkdirAll(filepath.Join(tmpDir, "node_modules", "express"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "node_modules", "express", "index.js"), []byte("// js"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644)

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
	os.MkdirAll(filepath.Join(tmpDir, "a", "b", "c", "d"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "a", "b", "c", "d", "deep.go"), []byte("package deep\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "a", "shallow.go"), []byte("package shallow\n"), 0644)

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
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "test_main.go"), []byte("package main\n"), 0644)

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
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module test\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644)

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
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\nfunc main() {}"), 0644)

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
	os.WriteFile(filepath.Join(tmpDir, "binary.txt"), data, 0644)

	input := &ScanInput{
		FileSet:  map[string]bool{"binary.txt": true},
		ScanRoot: tmpDir,
	}

	LoadFileContents(input, 1<<20)

	if _, ok := input.FileContents["binary.txt"]; ok {
		t.Error("binary file should be skipped")
	}
}
