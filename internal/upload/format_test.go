package upload

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFormat_ByFileName(t *testing.T) {
	tests := []struct {
		fileName string
		format   string
	}{
		{"bom.cdx.json", "cyclonedx"},
		{"cyclonedx-bom.json", "cyclonedx"},
		{"sbom.spdx.json", "spdx"},
		{"spdx-report.json", "spdx"},
		{"results.sarif.json", "sarif"},
		{"results.sarif", "sarif"},
		{"report.openvex.json", "openvex"},
		{"openvex-report.json", "openvex"},
		{"advisory.csaf.json", "csaf_vex"},
		{"csaf-report.json", "csaf_vex"},
	}
	for _, tc := range tests {
		got := DetectFormat(tc.fileName, nil)
		if got != tc.format {
			t.Errorf("DetectFormat(%q, nil): expected %q, got %q", tc.fileName, tc.format, got)
		}
	}
}

func TestDetectFormat_ByContent(t *testing.T) {
	tests := []struct {
		data   string
		format string
	}{
		{`{"bomFormat":"CycloneDX","specVersion":"1.5"}`, "cyclonedx"},
		{`{"spdxVersion":"SPDX-2.3"}`, "spdx"},
		{`{"$schema":"https://...sarif-schema-2.1.0.json"}`, "sarif"},
		{`{"@context":["https://openvex.dev/ns/v0.2.0"]}`, "openvex"},
	}
	for _, tc := range tests {
		got := DetectFormat("file.json", []byte(tc.data))
		if got != tc.format {
			t.Errorf("DetectFormat(%q): expected %q, got %q", string(tc.data), tc.format, got)
		}
	}
}

func TestDetectFormat_Auto(t *testing.T) {
	tests := []struct {
		fileName string
		data     string
	}{
		{"file.json", `{"foo":"bar"}`},
		{"file.txt", "plain text"},
		{"file.xml", "<root></root>"},
		{"", ""},
	}
	for _, tc := range tests {
		got := DetectFormat(tc.fileName, []byte(tc.data))
		if got != "auto" {
			t.Errorf("DetectFormat(%q, %q): expected 'auto', got %q", tc.fileName, tc.data, got)
		}
	}
}

func TestFindVulnetixDir_ProjectRelative(t *testing.T) {
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)

	// Create a temp dir with .vulnetix/ and override HOME so home fallback doesn't fire
	tmpDir := t.TempDir()
	os.MkdirAll(filepath.Join(tmpDir, ".vulnetix"), 0755)
	os.Chdir(tmpDir)
	t.Setenv("HOME", filepath.Join(tmpDir, "nonexistent-home"))

	dir, found := FindVulnetixDir()
	if !found {
		t.Fatal("expected found when ./.vulnetix exists")
	}
	if dir != ".vulnetix" {
		t.Errorf("expected '.vulnetix', got %q", dir)
	}
}

func TestFindVulnetixDir_NotFound(t *testing.T) {
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)

	// Override HOME to a non-existent dir so both paths fail
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	t.Setenv("HOME", filepath.Join(tmpDir, "nonexistent-home"))

	dir, found := FindVulnetixDir()
	if found {
		t.Errorf("expected not found, got %q", dir)
	}
}

func TestDiscoverVulnetixFiles_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	files, warnings, err := DiscoverVulnetixFiles(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d: %v", len(files), files)
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestDiscoverVulnetixFiles_SkipsMemory(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "memory.yaml"), []byte("key: val"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "credentials.json"), []byte("{}"), 0644)

	files, _, err := DiscoverVulnetixFiles(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range files {
		if filepath.Base(f.Path) == "memory.yaml" || filepath.Base(f.Path) == "credentials.json" {
			t.Errorf("should skip non-artifact file: %s", f.Path)
		}
	}
}

func TestNewClient(t *testing.T) {
	c := NewClient("https://custom.example.com", nil)
	if c.BaseURL != "https://custom.example.com" {
		t.Errorf("expected custom URL, got %q", c.BaseURL)
	}

	c2 := NewClient("", nil)
	if c2.BaseURL != DefaultBaseURL {
		t.Errorf("expected default URL, got %q", c2.BaseURL)
	}
}

func TestDefaultConstants(t *testing.T) {
	if DefaultChunkSize != 5*1024*1024 {
		t.Errorf("expected 5MB chunk size, got %d", DefaultChunkSize)
	}
	if ChunkThreshold != 10*1024*1024 {
		t.Errorf("expected 10MB threshold, got %d", ChunkThreshold)
	}
}
