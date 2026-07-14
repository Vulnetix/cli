// Package managedfile writes and reverts Vulnetix-owned regions of a user's
// config files without disturbing the rest of the file.
//
// A "managed block" is a run of lines fenced by a Start/End marker comment. The
// markers are a parameter, not a constant: the Package Firewall and the AI
// Firewall both write to the same shell rc, and each must be able to remove its
// own block without touching the other's.
package managedfile

import "strings"

// Markers fence a managed block. Both are whole-line comments in the target
// file's comment syntax (every format we write — sh, fish, csh, ini, toml,
// yaml, netrc — uses '#').
type Markers struct {
	Start string
	End   string
}

// Block wraps body in the markers and terminates it with a newline, which is
// the form Upsert expects.
func Block(m Markers, body string) string {
	return strings.Join([]string{
		m.Start,
		strings.TrimRight(body, "\n"),
		m.End,
		"",
	}, "\n")
}

// Upsert replaces the existing managed block in existing with block, or appends
// block if there is none. Content outside the markers is preserved.
func Upsert(existing, block string, m Markers) string {
	start := strings.Index(existing, m.Start)
	if start >= 0 {
		end := strings.Index(existing[start:], m.End)
		if end >= 0 {
			end += start + len(m.End)
			for end < len(existing) && (existing[end] == '\n' || existing[end] == '\r') {
				end++
			}
			prefix := strings.TrimRight(existing[:start], "\n")
			suffix := strings.TrimLeft(existing[end:], "\n")
			if prefix == "" {
				return block + suffix
			}
			return prefix + "\n\n" + block + suffix
		}
	}
	if strings.TrimSpace(existing) == "" {
		return block
	}
	return strings.TrimRight(existing, "\n") + "\n\n" + block
}

// Remove returns existing with the managed block (and its surrounding blank
// lines) removed. The bool reports whether a block was found.
func Remove(existing string, m Markers) (string, bool) {
	start := strings.Index(existing, m.Start)
	if start < 0 {
		return existing, false
	}
	end := strings.Index(existing[start:], m.End)
	if end < 0 {
		return existing, false
	}
	end += start + len(m.End)
	for end < len(existing) && (existing[end] == '\n' || existing[end] == '\r') {
		end++
	}
	prefix := strings.TrimRight(existing[:start], "\n")
	suffix := strings.TrimLeft(existing[end:], "\n")
	switch {
	case prefix == "" && suffix == "":
		return "", true
	case prefix == "":
		return suffix, true
	case suffix == "":
		return prefix + "\n", true
	default:
		return prefix + "\n\n" + suffix, true
	}
}
