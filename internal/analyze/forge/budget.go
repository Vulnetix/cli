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
	"fmt"
	"sync"

	"github.com/google/go-github/v66/github"
)

// reserve is the least number of requests we refuse to spend. Leaving headroom matters
// because this token is usually shared — with other steps in the same CI job, and in
// vdb-manager's case with other processors — and draining it to zero breaks them, not us.
const reserve = 100

// reserveShare is the fraction of the hourly limit we refuse to spend, when it is more than
// reserve. A fixed 100 was not enough headroom: inside GitHub Actions the job token's quota
// (1,000 an hour) belongs to the whole repository, and a forge pass on every push to the
// default branch spent it down to 100. CodeQL's SARIF upload and the release dispatch then
// failed with "API rate limit exceeded for installation". Keeping half the limit bounds
// what one run can take, whatever else runs beside it.
const reserveShare = 0.5

// floor is the remaining quota at which the collector stops, for a token with this hourly
// limit.
func floor(limit int) int {
	return max(reserve, int(float64(limit)*reserveShare))
}

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
		if b.remaining <= floor(b.limit) {
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

	return fmt.Sprintf("Stopped at this run's share of the GitHub API rate limit (%d of %d requests left, "+
		"kept for other jobs that share the token); the remaining items were not fetched. "+
		"Re-run when the quota resets, or narrow --forge-window-days.", b.remaining, b.limit)
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
