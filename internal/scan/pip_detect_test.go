package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePyTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDetectManifest_RequirementsVariations covers non-standard requirements
// filenames (matched by name pattern → confident) and arbitrary names matched by
// content (versioned/hashed → confident; bare names → tentative).
func TestDetectManifest_RequirementsVariations(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		rel, body, wantConf string
	}{
		{"requirements-dev.txt", "irrelevant content\n", ConfidenceConfident}, // name pattern wins, no read
		{"requirements/base.in", "irrelevant content\n", ConfidenceConfident}, // parent dir = requirements/
		{"constraints.txt", "irrelevant\n", ConfidenceConfident},
		{"app.pip", "irrelevant\n", ConfidenceConfident},                            // .pip extension
		{"deps.list", "flask==2.3.0\n    --hash=sha256:abc\n", ConfidenceConfident}, // content: versioned + hash
		{"names.lst", "flask\nrequests\nnumpy\n", ConfidenceTentative},              // content: bare names
	}
	for _, c := range cases {
		full := filepath.Join(dir, c.rel)
		writePyTestFile(t, full, c.body)
		info, ok := DetectManifest(full)
		if !ok {
			t.Errorf("%s: not detected", c.rel)
			continue
		}
		if info.Type != "requirements.txt" {
			t.Errorf("%s: type = %q, want requirements.txt", c.rel, info.Type)
		}
		if info.Ecosystem != "pypi" {
			t.Errorf("%s: ecosystem = %q, want pypi", c.rel, info.Ecosystem)
		}
		if info.Confidence != c.wantConf {
			t.Errorf("%s: confidence = %q, want %q", c.rel, info.Confidence, c.wantConf)
		}
	}
}

func TestDetectManifest_NotRequirements(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ rel, body string }{
		{"notes.txt", "This is prose with spaces.\nMore prose here.\n"}, // spaces → not requirements
		{"paths.txt", "src/foo.py\nsrc/bar.py\n"},                       // path separators
		{"readme.md", "flask\nrequests\n"},                              // .md not a sniff candidate
		{"data.txt", "key = value\nother = thing\n"},                    // assignment, not requirements
	}
	for _, c := range cases {
		full := filepath.Join(dir, c.rel)
		writePyTestFile(t, full, c.body)
		if info, ok := DetectManifest(full); ok {
			t.Errorf("%s: unexpectedly detected as %s (conf=%s)", c.rel, info.Type, info.Confidence)
		}
	}
}

func TestDetectManifest_OversizedNotSniffed(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "big.txt")
	var b strings.Builder
	for b.Len() < 300*1024 {
		b.WriteString("flask\n")
	}
	writePyTestFile(t, full, b.String())
	if _, ok := DetectManifest(full); ok {
		t.Error("a >256KB .txt must not be content-sniffed as requirements")
	}
}

func TestDetectManifest_PylockExact(t *testing.T) {
	info, ok := DetectManifest("pylock.toml")
	if !ok {
		t.Fatal("pylock.toml not detected")
	}
	if info.Type != "pylock.toml" || info.Ecosystem != "pypi" || !info.IsLock {
		t.Fatalf("pylock.toml: %+v", info)
	}
}

// Exact requirements.txt / requirements.in keep confident confidence.
func TestDetectManifest_ExactRequirementsConfident(t *testing.T) {
	for _, name := range []string{"requirements.txt", "requirements.in"} {
		info, ok := DetectManifest(name)
		if !ok || info.Confidence != ConfidenceConfident {
			t.Errorf("%s: ok=%v confidence=%q, want confident", name, ok, info.Confidence)
		}
	}
}
