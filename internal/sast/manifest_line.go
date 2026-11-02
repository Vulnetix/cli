package sast

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ManifestLines finds the line a package is declared on in a manifest, reading
// each manifest once. SCA and licence findings are about a package, not a
// line, but code scanning needs a line to open the alert on; the declaring
// line is the one a reviewer changes.
type ManifestLines struct {
	root  string
	files map[string][]string
}

// NewManifestLines resolves relative manifest paths against root.
func NewManifestLines(root string) *ManifestLines {
	return &ManifestLines{root: root, files: map[string][]string{}}
}

// Find returns the first line naming the package, quoted ("lodash") first and
// then as a bare word, or 0 when the manifest cannot be read or does not name
// it (a lockfile-only transitive dependency, for one).
func (m *ManifestLines) Find(source, name string) int {
	if m == nil || name == "" || source == "" {
		return 0
	}
	lines, ok := m.files[source]
	if !ok {
		path := source
		if !filepath.IsAbs(path) {
			path = filepath.Join(m.root, filepath.FromSlash(source))
		}
		if f, err := os.Open(path); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64*1024), 4<<20)
			for sc.Scan() {
				lines = append(lines, sc.Text())
			}
			_ = f.Close()
		}
		m.files[source] = lines
	}
	for _, quoted := range []string{`"` + name + `"`, `'` + name + `'`} {
		for i, l := range lines {
			if strings.Contains(l, quoted) {
				return i + 1
			}
		}
	}
	for i, l := range lines {
		if containsWord(l, name) {
			return i + 1
		}
	}
	return 0
}

// containsWord reports whether name appears in line with no package-name
// character on either side, so "react" does not match "react-dom".
func containsWord(line, name string) bool {
	for start := 0; start < len(line); {
		i := strings.Index(line[start:], name)
		if i < 0 {
			return false
		}
		i += start
		before := i == 0 || !isNameChar(line[i-1])
		end := i + len(name)
		after := end == len(line) || !isNameChar(line[end])
		if before && after {
			return true
		}
		start = i + 1
	}
	return false
}

func isNameChar(c byte) bool {
	return c == '-' || c == '_' || c == '.' || c == '/' || c == '@' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
