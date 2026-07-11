package forge

// The request budget.
//
// GitHub's rate limit is the single most common way a tool like this produces a wrong
// answer. There are three ways to get it wrong and all three are in the prior art:
//
//   - issue-metrics catches the rate-limit exception and calls sys.exit(1). The whole run is
//     lost, including the work already done.
//   - Several tools sleep until the reset, which for a core-quota exhaustion is up to an
//     hour. A CI job does not have an hour.
//   - The worst option, and the tempting one: catch the error, return what you have, and say
//     nothing. The report then quietly understates every count it touched, and looks exactly
//     like a report from a repository that simply has less going on.
//
// So: the budget stops the collector *before* the quota runs out, and what was not fetched
// is declared. A metric that ran out of budget is `truncated` with an `omittedCount` and a
// reason. It is not a failure, and it is not a silence.

import (
	"sync"

	"github.com/google/go-github/v66/github"
)

// reserve is the number of requests we refuse to spend. Leaving headroom matters because
// this token is usually shared — with other steps in the same CI job, and in vdb-manager's
// case with other processors — and draining it to zero breaks them, not us.
const reserve = 100

type budget struct {
	mu sync.Mutex

	remaining int
	limit     int
	known     bool

	// spent counts requests we made. Used when GitHub does not tell us the remaining quota
	// (enterprise instances sometimes do not) so we can still bound the work.
	spent int

	exhausted bool
}

func newBudget() *budget {
	return &budget{}
}

// Observe records the rate-limit state GitHub reported on a response. Every call the
// collector makes should pass its response through here.
func (b *budget) Observe(resp *github.Response) {
	if resp == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.spent++
	if resp.Rate.Limit > 0 {
		b.remaining = resp.Rate.Remaining
		b.limit = resp.Rate.Limit
		b.known = true
		if b.remaining <= reserve {
			b.exhausted = true
		}
	}
}

// Exhausted reports whether the collector should stop. A caller that ignores this and keeps
// going will get a 403 and lose the run; a caller that respects it keeps everything it has
// already gathered.
func (b *budget) Exhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.exhausted
}

// Remaining reports the quota left, and whether GitHub actually told us.
func (b *budget) Remaining() (n int, known bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.remaining, b.known
}

// Spent reports how many requests were made.
func (b *budget) Spent() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.spent
}

// Reason explains, in the words that will end up in the report's truncationReason, why the
// collector stopped early.
func (b *budget) Reason() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.exhausted {
		return ""
	}

	return "GitHub API rate limit reached; the remaining items were not fetched. " +
		"Re-run when the quota resets, or narrow --window-days."
}

// IsRateLimit reports whether an error is GitHub telling us to stop. Distinguishing it from
// a real failure matters: one means "come back later", the other means something is broken,
// and treating them the same makes both harder to diagnose.
func IsRateLimit(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*github.RateLimitError); ok {
		return true
	}
	if _, ok := err.(*github.AbuseRateLimitError); ok {
		return true
	}

	return false
}
