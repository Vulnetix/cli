// Package efficacy measures whether a SAST rule does what it says: it reports
// the defect it was written for, in the shapes that defect takes, and stays
// quiet on the code that merely resembles it.
//
// A case is a directory of real files under testdata/efficacy/<rule>/<case>/.
// A line that begins with the marker "~>" is a line the rule must report; the
// marker is removed before the files are scanned, so the scanner sees exactly
// the code a developer would have written. Every other line in the case must
// not be reported. A case with no marker is a pure false-positive trap.
//
// Cases are evaluated through the production engine (sast.NewEngine and
// Evaluate), so the input builder, the language filter, content loading and
// the per-finding file scope all apply exactly as they do in a scan.
package efficacy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Marker is the line prefix that marks a line the rule must report.
const Marker = "~>"

// Loc is a reported or expected position.
type Loc struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

func (l Loc) String() string { return fmt.Sprintf("%s:%d", l.File, l.Line) }

// Case is one fixture directory for one rule.
type Case struct {
	Rule  string            `json:"rule"` // rule file stem, e.g. "vnx-go-014"
	Name  string            `json:"name"` // case directory name
	Dir   string            `json:"dir"`
	Files map[string]string `json:"-"` // relative path → content, markers removed
	Want  []Loc             `json:"want"`
}

// Positive reports whether the case expects at least one finding.
func (c Case) Positive() bool { return len(c.Want) > 0 }

// StripMarkers removes "~>" markers and returns the cleaned text with the
// 1-based lines that carried one.
func StripMarkers(src string) (string, []int) {
	lines := strings.Split(src, "\n")
	var want []int
	for i, l := range lines {
		if strings.HasPrefix(l, Marker) {
			lines[i] = l[len(Marker):]
			want = append(want, i+1)
		}
	}
	return strings.Join(lines, "\n"), want
}

// LoadCases reads every case under root (root/<rule>/<case>/...). When rules
// is non-empty only those rule stems are loaded.
func LoadCases(root string, rules ...string) ([]Case, error) {
	only := map[string]bool{}
	for _, r := range rules {
		only[strings.TrimSuffix(r, ".rego")] = true
	}
	ruleDirs, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Case
	for _, rd := range ruleDirs {
		if !rd.IsDir() || (len(only) > 0 && !only[rd.Name()]) {
			continue
		}
		caseDirs, err := os.ReadDir(filepath.Join(root, rd.Name()))
		if err != nil {
			return nil, err
		}
		for _, cd := range caseDirs {
			if !cd.IsDir() {
				continue
			}
			c, err := loadCase(filepath.Join(root, rd.Name(), cd.Name()), rd.Name(), cd.Name())
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func loadCase(dir, rule, name string) (Case, error) {
	c := Case{Rule: rule, Name: name, Dir: dir, Files: map[string]string{}}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		expanded, err := ExpandSamples(string(b), rel)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		clean, lines := StripMarkers(expanded)
		c.Files[rel] = clean
		for _, l := range lines {
			c.Want = append(c.Want, Loc{rel, l})
		}
		return nil
	})
	sortLocs(c.Want)
	return c, err
}

func sortLocs(ls []Loc) {
	sort.Slice(ls, func(i, j int) bool {
		if ls[i].File != ls[j].File {
			return ls[i].File < ls[j].File
		}
		return ls[i].Line < ls[j].Line
	})
}

var ruleIDRe = regexp.MustCompile(`"id"\s*:\s*"([^"]+)"`)

// RuleID returns the metadata id declared by a rule module.
func RuleID(src string) string {
	if m := ruleIDRe.FindStringSubmatch(src); m != nil {
		return m[1]
	}
	return ""
}

// samplePlaceholder is "@@sample:REGEX@@". A case that needs a credential of a
// real provider's shape writes the shape, not a token: committing tokens of
// live formats trips provider push protection and is a leak-shaped artefact
// in its own right. The placeholder is replaced, at load time, by a random
// string the regular expression matches (deterministic per file and line).
var samplePlaceholder = regexp.MustCompile(`@@sample:(.+?)@@`)

// ExpandSamples replaces every @@sample:REGEX@@ in src.
func ExpandSamples(src, file string) (string, error) {
	if !strings.Contains(src, "@@sample:") {
		return src, nil
	}
	var firstErr error
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		n := 0
		lines[i] = samplePlaceholder.ReplaceAllStringFunc(line, func(m string) string {
			pat := samplePlaceholder.FindStringSubmatch(m)[1]
			seed := len(file)*31 + i*7 + n
			n++
			full, _, err := SampleMode(pat, seed, modeRandom)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("line %d: %w", i+1, err)
				}
				return m
			}
			return full
		})
	}
	return strings.Join(lines, "\n"), firstErr
}
