package ghtasks

import (
	"context"
	"sync"

	"github.com/Vulnetix/vdb-sca-match/ghaudit"
)

// AdvisoryLookup answers one action reference: the advisories that affect the
// version its ref names. ok=false means the lookup failed.
type AdvisoryLookup func(ctx context.Context, action, ref string) (ids []ghaudit.ActionAdvisory, ok bool)

// Advisories adapts a lookup to ghaudit.CollectOptions.Advisories, asking once
// per action@ref. Failed reports whether any lookup failed, so the caller can
// say the known-vulnerable rule was not fully evaluated.
type Advisories struct {
	Lookup AdvisoryLookup
	mu     sync.Mutex
	cache  map[string][]ghaudit.ActionAdvisory
	Failed bool
	Asked  int
}

// Func returns the callback for CollectOptions.Advisories.
func (a *Advisories) Func() func(ctx context.Context, action, ref, sha string) []ghaudit.ActionAdvisory {
	return func(ctx context.Context, action, ref, _ string) []ghaudit.ActionAdvisory {
		key := action + "@" + ref
		a.mu.Lock()
		if a.cache == nil {
			a.cache = map[string][]ghaudit.ActionAdvisory{}
		}
		if v, seen := a.cache[key]; seen {
			a.mu.Unlock()
			return v
		}
		a.mu.Unlock()
		out, ok := a.Lookup(ctx, action, ref)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.Asked++
		if !ok {
			a.Failed = true
		}
		a.cache[key] = out
		return out
	}
}
