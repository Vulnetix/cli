package ignore

import (
	"math/rand"
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

// TestGlobs pins the --exclude/--ignore spellings people actually type. Each
// of the directory forms used to be matched with filepath.Match, which never
// matches "testdata/" against "testdata", so the directory was walked anyway.
func TestGlobs(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		isDir   bool
		want    bool
	}{
		{"testdata/", "testdata", true, true},
		{"testdata/", "testdata/a/package.json", false, true},
		{"testdata/", "sub/testdata", true, true},
		{"testdata/", "testdata", false, false}, // a file of that name is not a directory
		{"testdata", "sub/testdata", true, true},
		{"./testdata/", "testdata", true, true},
		{"./testdata/", "sub/testdata", true, false}, // a path with a slash is root-anchored
		{"testdata/**", "testdata/a/b/package.json", false, true},
		{"**/testdata/**", "x/y/testdata/package.json", false, true},
		{"sub/*.json", "sub/package.json", false, true},
		{"sub/*.json", "other/sub/package.json", false, false},
		{"*_test.go", "pkg/foo_test.go", false, true},
		{"testdata/", "testdata2", true, false},
		{"testdata/", "src/main.go", false, false},
		{"./.github/", ".github/workflows/ci.yml", false, true},
	}
	for _, c := range cases {
		if got := Globs([]string{c.pattern}).Ignored(c.path, c.isDir); got != c.want {
			t.Errorf("Globs(%q).Ignored(%q, dir=%v) = %v, want %v", c.pattern, c.path, c.isDir, got, c.want)
		}
	}
}

// The substring prefilters only skip a regexp that could not have matched:
// over random rule sets and paths, every answer is the one the regexps alone
// give.
func TestLiteralFiltersChangeNoAnswer(t *testing.T) {
	names := []string{"node_modules", "build", "dist", "*.log", "a", "ab", "x?z", "[bc]at", "**", "**/tmp", "docs/*.tmp", "keep.log", "vendor", "*.min.js", "a/**/b", ".env", "*~"}
	segs := []string{"node_modules", "build", "dist", "app.log", "a", "ab", "xyz", "cat", "bat", "tmp", "docs", "x.tmp", "keep.log", "vendor", "y.min.js", "b", ".env", "f~", "src", "\n", "é", "Build"}
	rng := rand.New(rand.NewSource(3))
	for range 200 {
		var lines []string
		for range 1 + rng.Intn(10) {
			p := names[rng.Intn(len(names))]
			switch rng.Intn(5) {
			case 0:
				p = "/" + p
			case 1:
				p += "/"
			case 2:
				p = "!" + p
			}
			lines = append(lines, p)
		}
		m := New()
		m.addPatterns("", strings.Join(lines, "\n"))
		m.addPatterns(segs[rng.Intn(len(segs))], strings.Join(lines[:len(lines)/2], "\n"))
		for range 200 {
			var parts []string
			for range 1 + rng.Intn(5) {
				parts = append(parts, segs[rng.Intn(len(segs))])
			}
			path, isDir := strings.Join(parts, "/"), rng.Intn(2) == 0
			literalFilters = false
			want := m.Ignored(path, isDir)
			literalFilters = true
			if got := m.Ignored(path, isDir); got != want {
				t.Fatalf("rules %q, path %q dir=%v: filtered %v, regexps %v", lines, path, isDir, got, want)
			}
		}
	}
}
