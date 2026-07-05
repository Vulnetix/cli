// Package ignore implements .gitignore-style path matching shared by the
// scan and sast filesystem walkers.
package ignore

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Matcher evaluates paths against a stack of .gitignore files
// discovered during a top-down filesystem walk. It implements the subset of
// gitignore(5) semantics that matters for scan pruning: comments, negation
// (`!`), anchored patterns (leading or embedded `/`), directory-only patterns
// (trailing `/`), and `*` / `?` / `**` / `[...]` globs.
//
// Rules are accumulated per directory: call LoadDir on each directory as the
// walk enters it (parents before children, which filepath.WalkDir guarantees),
// then Ignored to test each entry. Because ignored directories are pruned with
// SkipDir, a negation cannot re-include a file whose parent directory is
// ignored — this matches git's own behaviour.
type Matcher struct {
	rules []gitignoreRule
}

type gitignoreRule struct {
	baseDir string // slash relative dir the .gitignore lives in ("" = root)
	negate  bool
	dirOnly bool
	core    *regexp.Regexp // matches the entry itself
	under   *regexp.Regexp // matches any path beneath a matched directory
}

// New returns an empty matcher.
func New() *Matcher { return &Matcher{} }

// LoadDir reads a .gitignore in absDir (whose slash-relative path from the walk
// root is relDir, "" for the root) and appends its rules. Missing or unreadable
// files are silently ignored.
func (m *Matcher) LoadDir(absDir, relDir string) {
	data, err := os.ReadFile(filepath.Join(absDir, ".gitignore"))
	if err != nil {
		return
	}
	m.addPatterns(relDir, string(data))
}

func (m *Matcher) addPatterns(baseDir, content string) {
	baseDir = strings.Trim(filepath.ToSlash(baseDir), "/")
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		// Trailing whitespace is not significant unless escaped; we do not
		// support escaped trailing spaces (vanishingly rare in real repos).
		line = strings.TrimRight(line, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule := gitignoreRule{baseDir: baseDir}
		if strings.HasPrefix(line, "!") {
			rule.negate = true
			line = line[1:]
		}
		// Unescape a leading \# or \! literal.
		if strings.HasPrefix(line, `\#`) || strings.HasPrefix(line, `\!`) {
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			rule.dirOnly = true
			line = strings.TrimSuffix(line, "/")
		}
		if line == "" {
			continue
		}
		// A pattern is anchored to baseDir if it has a leading slash or an
		// embedded slash; otherwise it matches a basename at any depth.
		anchored := strings.HasPrefix(line, "/") || strings.Contains(line, "/")
		line = strings.TrimPrefix(line, "/")
		rule.core, rule.under = compileGitignoreGlob(line, anchored)
		if rule.core != nil {
			m.rules = append(m.rules, rule)
		}
	}
}

// Ignored reports whether the slash-relative path (relPath) should be excluded.
// Later matching rules win, so negations placed after a broad ignore re-include.
func (m *Matcher) Ignored(relPath string, isDir bool) bool {
	relPath = strings.Trim(filepath.ToSlash(relPath), "/")
	if relPath == "" {
		return false
	}
	matched := false
	for _, r := range m.rules {
		local := relPath
		if r.baseDir != "" {
			if !strings.HasPrefix(relPath, r.baseDir+"/") {
				continue
			}
			local = relPath[len(r.baseDir)+1:]
		}
		if r.under.MatchString(local) {
			// Path is beneath a matched directory — always ignored.
			matched = !r.negate
			continue
		}
		if r.core.MatchString(local) {
			if r.dirOnly && !isDir {
				continue
			}
			matched = !r.negate
		}
	}
	return matched
}

// compileGitignoreGlob converts a single gitignore pattern into two anchored
// regexps over a slash path: core matches the entry itself, under matches any
// path strictly beneath it (so a matched directory ignores its whole subtree).
// When anchored is false the pattern matches the final path component at any
// depth.
func compileGitignoreGlob(pattern string, anchored bool) (core, under *regexp.Regexp) {
	body := globToRegex(pattern)
	prefix := "^"
	if !anchored {
		// Unanchored: match either the whole path or any trailing segment.
		prefix = "^(?:.*/)?"
	}
	coreRe, err := regexp.Compile(prefix + body + "$")
	if err != nil {
		return nil, nil
	}
	underRe, err := regexp.Compile(prefix + body + "/.*$")
	if err != nil {
		return nil, nil
	}
	return coreRe, underRe
}

func globToRegex(glob string) string {
	var b strings.Builder
	runes := []rune(glob)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch c {
		case '*':
			if i+1 < len(runes) && runes[i+1] == '*' {
				// ** — spans directory separators.
				i++
				if i+1 < len(runes) && runes[i+1] == '/' {
					i++ // consume the slash: **/ matches zero or more dirs
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			// Copy a character class verbatim until the closing ].
			j := i + 1
			if j < len(runes) && (runes[j] == '!' || runes[j] == '^') {
				j++
			}
			if j < len(runes) && runes[j] == ']' {
				j++
			}
			for j < len(runes) && runes[j] != ']' {
				j++
			}
			if j < len(runes) {
				class := string(runes[i : j+1])
				if strings.HasPrefix(class, "[!") {
					class = "[^" + class[2:]
				}
				b.WriteString(class)
				i = j
			} else {
				b.WriteString(`\[`)
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}
