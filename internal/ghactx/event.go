// Package ghactx collects the CI identity of a GitHub Actions run.
//
// In a runner the git checkout is a detached HEAD, so the local repository is
// not a usable source of branch or repo identity. The environment is, and the
// webhook payload GitHub writes to GITHUB_EVENT_PATH is richer still: it carries
// the repository's id, visibility, default branch and licence, and for a
// pull_request event the PR number and both refs — all without a network call.
package ghactx

import (
	"encoding/json"
	"os"
)

// Event is the webhook payload GitHub wrote to disk for this run, held as a
// generic tree because its shape depends on the event type and only a handful of
// paths are ever read.
type Event struct {
	raw map[string]any
}

// LoadEvent reads GITHUB_EVENT_PATH. Returns nil when the variable is unset or
// the file is unreadable — every accessor tolerates a nil receiver, so callers
// need no branch for it.
func LoadEvent() *Event {
	path := os.Getenv("GITHUB_EVENT_PATH")
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}
	return &Event{raw: raw}
}

// EventFromJSON parses a payload from bytes. Used by tests and by --from-dir
// runs replaying a captured event.
func EventFromJSON(b []byte) *Event {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}
	return &Event{raw: raw}
}

// lookup walks a dotted path through the payload.
func (e *Event) lookup(path ...string) any {
	if e == nil || e.raw == nil {
		return nil
	}
	var cur any = e.raw
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[key]
		if !ok {
			return nil
		}
	}
	return cur
}

// String reads a string at the given path.
func (e *Event) String(path ...string) string {
	s, _ := e.lookup(path...).(string)
	return s
}

// Int64 reads a number at the given path. JSON numbers decode as float64, which
// is exact for GitHub's ids up to 2^53 — comfortably beyond current values.
func (e *Event) Int64(path ...string) int64 {
	switch v := e.lookup(path...).(type) {
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return 0
	}
}

// Int reads a number at the given path as an int.
func (e *Event) Int(path ...string) int {
	return int(e.Int64(path...))
}

// Bool reads a boolean at the given path.
func (e *Event) Bool(path ...string) bool {
	b, _ := e.lookup(path...).(bool)
	return b
}

// Has reports whether a value exists at the given path.
func (e *Event) Has(path ...string) bool {
	return e.lookup(path...) != nil
}
