// Package ghquota is the GitHub API request budget every caller of the API in this CLI
// shares the design of: analyze's forge pass and the licence lookups.
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
// So: the budget stops the caller *before* the quota runs out, and what was not fetched is
// declared. A metric that ran out of budget is `truncated` with an `omittedCount` and a
// reason. It is not a failure, and it is not a silence.
//
// Inside GitHub Actions the job token's quota belongs to the whole repository, so the
// remaining count a response reports is the same number in every job of the run. A floor on
// it is therefore a floor for the run, not just for this process: every job that stops at
// it stops at the same level, however many run at once.
package ghquota

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/google/go-github/v66/github"
)

// reserve is the least number of requests we refuse to spend. Leaving headroom matters
// because this token is usually shared — with other steps in the same CI job, and in
// vdb-manager's case with other processors — and draining it to zero breaks them, not us.
const reserve = 100

// DefaultShare is the fraction of the hourly limit a budget refuses to spend, when it is
// more than reserve. A fixed 100 was not enough headroom: inside GitHub Actions the job
// token's quota (1,000 an hour, 5,000 for an organisation's installation) belongs to the
// whole repository, and a forge pass on every push to the default branch spent it down to
// 100. CodeQL's SARIF upload and the release dispatch then failed with "API rate limit
// exceeded for installation". Keeping half the limit bounds what one run can take, whatever
// else runs beside it.
const DefaultShare = 0.5

// DefaultHint is the advice Reason ends with unless the caller gives its own.
const DefaultHint = "Re-run when the quota resets, or narrow --forge-window-days."

// Budget bounds a caller's GitHub API requests. It is safe for concurrent use.
type Budget struct {
	mu sync.Mutex

	share float64
	hint  string

	remaining int
	limit     int
	known     bool

	// spent counts requests we made. Used when GitHub does not tell us the remaining quota
	// (enterprise instances sometimes do not) so we can still bound the work.
	spent int

	exhausted bool
	// refused is set when GitHub itself answered with a rate limit, as opposed to the
	// budget stopping at its floor.
	refused bool
}

// Option configures a Budget.
type Option func(*Budget)

// Keep sets the fraction of the hourly limit the budget refuses to spend. A caller whose
// requests matter less than the other users of the token keeps more.
func Keep(share float64) Option { return func(b *Budget) { b.share = share } }

// Hint sets the advice Reason ends with.
func Hint(h string) Option { return func(b *Budget) { b.hint = h } }

// NewBudget returns a budget that keeps DefaultShare of the limit.
func NewBudget(opts ...Option) *Budget {
	b := &Budget{share: DefaultShare, hint: DefaultHint}
	for _, o := range opts {
		o(b)
	}
	return b
}

// floor is the remaining quota at which the budget stops, for a token with this hourly
// limit.
func (b *Budget) floor(limit int) int {
	return max(reserve, int(float64(limit)*b.share))
}

// Observe records the rate-limit state GitHub reported on a response. Every call the
// caller makes should pass its response through here.
func (b *Budget) Observe(resp *github.Response) {
	if resp == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.spent++
	if resp.Rate.Limit > 0 {
		b.setRate(resp.Rate.Limit, resp.Rate.Remaining)
	}
}

// ObserveHTTP is Observe for a response read with net/http rather than go-github. A
// response that is GitHub refusing the request for its rate limit, primary or secondary,
// exhausts the budget whatever the headers say.
func (b *Budget) ObserveHTTP(r *http.Response) {
	if r == nil {
		return
	}
	rate := github.Rate{}
	rate.Limit, _ = strconv.Atoi(r.Header.Get("X-RateLimit-Limit"))
	rate.Remaining, _ = strconv.Atoi(r.Header.Get("X-RateLimit-Remaining"))
	b.Observe(&github.Response{Response: r, Rate: rate})
	switch r.StatusCode {
	case http.StatusTooManyRequests:
		b.Refused()
	case http.StatusForbidden:
		if IsRateLimit(github.CheckResponse(r)) {
			b.Refused()
		}
	}
}

// Spend counts a request whose response carried no rate-limit state the caller could read
// (one made through the gh CLI, say). It still counts toward Spent.
func (b *Budget) Spend() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spent++
}

// Seed records the quota GitHub reported before any request was spent (GET /rate_limit,
// which does not count against it). A caller that starts below the floor spends nothing.
func (b *Budget) Seed(limit, remaining int) {
	if limit <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.setRate(limit, remaining)
}

func (b *Budget) setRate(limit, remaining int) {
	b.remaining = remaining
	b.limit = limit
	b.known = true
	if b.remaining <= b.floor(b.limit) {
		b.exhausted = true
	}
}

// Refused records that GitHub answered with a rate limit. Nothing more is asked: every
// further request would be refused the same way.
func (b *Budget) Refused() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.exhausted = true
	b.refused = true
}

// Exhausted reports whether the caller should stop. A caller that ignores this and keeps
// going will get a 403 and lose the run; a caller that respects it keeps everything it has
// already gathered.
func (b *Budget) Exhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.exhausted
}

// Remaining reports the quota left, and whether GitHub actually told us.
func (b *Budget) Remaining() (n int, known bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.remaining, b.known
}

// Limit reports the hourly limit, and whether GitHub actually told us.
func (b *Budget) Limit() (n int, known bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.limit, b.known
}

// Spent reports how many requests were made.
func (b *Budget) Spent() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.spent
}

// Reason explains, in the words that will end up in the report's truncationReason, why the
// caller stopped early.
func (b *Budget) Reason() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.exhausted {
		return ""
	}
	if b.refused && (!b.known || b.remaining > b.floor(b.limit)) {
		return "Stopped because GitHub answered that the API rate limit for this token is exhausted; " +
			"the remaining items were not fetched. " + b.hint
	}

	return fmt.Sprintf("Stopped at this run's share of the GitHub API rate limit (%d of %d requests left, "+
		"kept for other jobs that share the token); the remaining items were not fetched. %s",
		b.remaining, b.limit, b.hint)
}

// IsRateLimit reports whether an error is GitHub telling us to stop. Distinguishing it from
// a real failure matters: one means "come back later", the other means something is broken,
// and treating them the same makes both harder to diagnose.
func IsRateLimit(err error) bool {
	var rl *github.RateLimitError
	var abuse *github.AbuseRateLimitError

	return errors.As(err, &rl) || errors.As(err, &abuse)
}
