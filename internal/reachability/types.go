// Package reachability runs tree-sitter S-expression queries supplied
// by vdb-manager against source files to determine whether a known-
// vulnerable code pattern is present (direct mode) or reachable from
// first-party code (transitive mode).
package reachability

// Mode selects which scans are performed.
type Mode string

const (
	ModeOff        Mode = "off"
	ModeDirect     Mode = "direct"
	ModeTransitive Mode = "transitive"
	ModeBoth       Mode = "both"
)

// ParseMode normalises user input. The empty string maps to ModeBoth
// (the default).
func ParseMode(s string) (Mode, bool) {
	switch s {
	case "", "both":
		return ModeBoth, true
	case "direct":
		return ModeDirect, true
	case "transitive":
		return ModeTransitive, true
	case "off", "none", "false", "0":
		return ModeOff, true
	}
	return "", false
}

// Includes reports whether the given mode is active under m.
func (m Mode) Includes(other Mode) bool {
	if m == ModeOff {
		return false
	}
	if m == ModeBoth {
		return true
	}
	return m == other
}

// Match is one tree-sitter query hit recorded against a file.
type Match struct {
	File      string            `json:"file"`
	StartLine int               `json:"start_line"`
	EndLine   int               `json:"end_line"`
	Query     string            `json:"query,omitempty"`
	Language  string            `json:"language,omitempty"`
	Captures  map[string]string `json:"captures,omitempty"`
}

// Range renders StartLine:EndLine using the "n:n" convention used in
// the rest of the CLI's output.
func (m Match) Range() string {
	if m.StartLine == m.EndLine {
		return itoa(m.StartLine) + ":" + itoa(m.EndLine)
	}
	return itoa(m.StartLine) + ":" + itoa(m.EndLine)
}

// Result is the full reachability output for a single vulnerability.
type Result struct {
	Direct     []Match `json:"direct,omitempty"`
	Transitive []Match `json:"transitive,omitempty"`
	// Skipped is populated when a mode was requested but couldn't run,
	// e.g. the package install folder couldn't be located.
	SkippedDirect     string `json:"skipped_direct,omitempty"`
	SkippedTransitive string `json:"skipped_transitive,omitempty"`
	// QueriesRun is the count of distinct query/language pairs executed.
	QueriesRun int `json:"queries_run"`
	// Executed is the set of query identities (see QueryKey) that compiled and
	// ran against at least one matching-language source file. A query whose
	// language was unsupported, had no files in the scanned tree, or failed to
	// compile for every file is absent — callers must not treat its CVE as
	// assessed.
	Executed map[string]bool `json:"executed,omitempty"`
}

// Empty reports whether no matches were recorded.
func (r *Result) Empty() bool {
	return r == nil || (len(r.Direct) == 0 && len(r.Transitive) == 0)
}

// itoa is a tiny local int-to-string to avoid pulling strconv into the
// hot path; ranges are small positive ints.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 6)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
