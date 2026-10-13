package defences

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

var (
	sourceMu      sync.RWMutex
	currentSource Source = &vdbSource{}
)

// DefaultSource returns the Source the CLI uses.
func DefaultSource() Source {
	sourceMu.RLock()
	defer sourceMu.RUnlock()
	return currentSource
}

// SetSource replaces the default Source and returns a function that restores it.
// It exists for tests.
func SetSource(s Source) (restore func()) {
	sourceMu.Lock()
	prev := currentSource
	currentSource = s
	sourceMu.Unlock()
	return func() {
		sourceMu.Lock()
		currentSource = prev
		sourceMu.Unlock()
	}
}

// StaticSource is an in-memory Source. It is a complete implementation, not a
// mock: it answers exactly as the API would, including withholding rule details
// from a caller that is not Pro.
type StaticSource struct {
	// Summaries is keyed by upper-case identifier.
	Summaries map[string]Summary
	// Bodies is keyed by rule UUID.
	Bodies map[string]Body
}

func (s StaticSource) Lookup(_ context.Context, ids []string, opts LookupOptions) (map[string]Summary, error) {
	out := make(map[string]Summary, len(ids))
	for _, id := range ids {
		sum, ok := s.Summaries[normalise(id)]
		if !ok {
			out[id] = Summary{ID: id, State: StateNone}
			continue
		}
		sum.ID = id
		if !opts.Pro {
			sum.Block.Rules, sum.Detect.Rules = nil, nil
		}
		sum.Classify()
		out[id] = sum
	}
	return out, nil
}

func (s StaticSource) Download(_ context.Context, rule Rule) (Body, error) {
	if rule.ArchiveURL == "" {
		return Body{}, fmt.Errorf("rule %s has no archive URL: rule downloads need a Pro plan", rule.ArtifactID)
	}
	b, ok := s.Bodies[rule.UUID]
	if !ok {
		return Body{}, fmt.Errorf("rule %s not found", rule.ArtifactID)
	}
	return b, nil
}

func normalise(id string) string { return strings.ToUpper(strings.TrimSpace(id)) }
