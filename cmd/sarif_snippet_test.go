package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureSnippet is the only thing --snippet-context changes, and it shapes the
// finding payload sent to the API rather than the SARIF written to disk. That
// makes the flag invisible to an unauthenticated run, so it had no coverage at
// all — this pins the documented semantics instead.
func TestCaptureSnippetContextSemantics(t *testing.T) {
	root := t.TempDir()
	// 12 lines, with a blank line inside the leading context so the
	// skip-blanks-while-counting rule is exercised.
	body := strings.Join([]string{
		"package main",  // 1
		"",              // 2  (blank: not counted as context, still emitted)
		"import \"os\"", // 3
		"",              // 4  (blank)
		"func a() {}",   // 5
		"func b() {}",   // 6
		"func target()", // 7  <- finding
		"func c() {}",   // 8
		"func d() {}",   // 9
		"func e() {}",   // 10
		"func f() {}",   // 11
		"func g() {}",   // 12
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("zero disables capture", func(t *testing.T) {
		snip, start, end := captureSnippet(root, "main.go", 7, 7, 0)
		if snip != "" || start != 0 || end != 0 {
			t.Fatalf("expected no capture, got %q (%d-%d)", snip, start, end)
		}
	})

	t.Run("positive takes that many non-blank lines each side", func(t *testing.T) {
		snip, start, end := captureSnippet(root, "main.go", 7, 7, 2)
		if !strings.Contains(snip, "func target()") {
			t.Fatalf("snippet lost the finding line: %q", snip)
		}
		if start >= 7 || end <= 7 {
			t.Fatalf("expected context on both sides of line 7, got %d-%d", start, end)
		}
		// Two non-blank lines above line 7 are 6 and 5; two below are 8 and 9.
		if start != 5 || end != 9 {
			t.Fatalf("range = %d-%d, want 5-9", start, end)
		}
	})

	t.Run("negative is dynamic: 3 lines for a short span", func(t *testing.T) {
		snip, start, end := captureSnippet(root, "main.go", 7, 7, -1)
		// Counting up from 7 for three non-blank lines reaches 6 and 5, skips the
		// blank at 4 without counting it, and lands on 3 — so the range is 3-10 and
		// the blank line is still emitted, keeping the text aligned to real line
		// numbers.
		if start != 3 || end != 10 {
			t.Fatalf("range = %d-%d, want 3-10 (3 non-blank lines each side)", start, end)
		}
		if lines := strings.Split(snip, "\n"); len(lines) != 8 || strings.TrimSpace(lines[1]) != "" {
			t.Fatalf("blank context line should be retained in the text, got %q", snip)
		}
	})

	t.Run("negative is dynamic: 5 lines for a span of 10+", func(t *testing.T) {
		// A span from 1 to 12 is 12 lines, so the dynamic rule picks 5.
		_, start, end := captureSnippet(root, "main.go", 1, 12, -1)
		if start != 1 || end != 12 {
			t.Fatalf("range = %d-%d, want the whole file clamped to 1-12", start, end)
		}
	})

	t.Run("missing file and bad lines capture nothing", func(t *testing.T) {
		if snip, _, _ := captureSnippet(root, "absent.go", 3, 3, 3); snip != "" {
			t.Errorf("missing file should capture nothing, got %q", snip)
		}
		if snip, _, _ := captureSnippet(root, "main.go", 0, 0, 3); snip != "" {
			t.Errorf("line 0 should capture nothing, got %q", snip)
		}
		if snip, _, _ := captureSnippet(root, "main.go", 99, 99, 3); snip != "" {
			t.Errorf("line past EOF should capture nothing, got %q", snip)
		}
		if snip, _, _ := captureSnippet(root, "", 3, 3, 3); snip != "" {
			t.Errorf("empty path should capture nothing, got %q", snip)
		}
	})

	t.Run("end before start is treated as a single line", func(t *testing.T) {
		_, start, end := captureSnippet(root, "main.go", 7, 3, 1)
		if start != 6 || end != 8 {
			t.Fatalf("range = %d-%d, want 6-8", start, end)
		}
	})
}
