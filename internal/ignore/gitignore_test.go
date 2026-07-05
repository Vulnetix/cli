package ignore

import (
	"strings"
	"testing"
)

func TestMatcher(t *testing.T) {
	m := New()
	m.addPatterns("", strings.Join([]string{
		"# comment",
		"*.log",
		"build/",
		"/root-only.txt",
		"docs/*.tmp",
		"node_modules",
		"dist/**",
		"!keep.log",
		"secrets_decoy/",
	}, "\n"))

	cases := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"app.log", false, true},            // *.log any depth
		{"a/b/app.log", false, true},        // *.log nested
		{"keep.log", false, false},          // negated after *.log
		{"build", true, true},               // dir-only match
		{"build/x.o", false, true},          // under ignored dir (prefix rule)
		{"root-only.txt", false, true},      // anchored root
		{"sub/root-only.txt", false, false}, // anchored: not at root
		{"docs/notes.tmp", false, true},     // docs/*.tmp
		{"docs/a/notes.tmp", false, false},  // single * does not cross slash
		{"node_modules", true, true},        // basename dir
		{"pkg/node_modules", true, true},    // basename at depth
		{"dist/a/b.js", false, true},        // dist/** deep
		{"secrets_decoy", true, true},       // decoy dir used in verification
		{"src/main.go", false, false},       // not ignored
	}
	for _, c := range cases {
		if got := m.Ignored(c.path, c.isDir); got != c.want {
			t.Errorf("Ignored(%q, dir=%v) = %v, want %v", c.path, c.isDir, got, c.want)
		}
	}
}

func TestGitignoreNestedBaseDir(t *testing.T) {
	m := New()
	m.addPatterns("", "*.log\n")
	m.addPatterns("sub", "local.txt\n") // .gitignore inside sub/
	if !m.Ignored("sub/local.txt", false) {
		t.Errorf("expected sub/local.txt ignored by nested .gitignore")
	}
	if m.Ignored("local.txt", false) {
		t.Errorf("root local.txt must NOT be ignored by sub/.gitignore")
	}
}
