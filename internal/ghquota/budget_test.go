package ghquota

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func response(status, limit, remaining int, body string) *http.Response {
	h := http.Header{}
	if limit > 0 {
		h.Set("X-RateLimit-Limit", strconv.Itoa(limit))
		h.Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/o/r", nil)
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

// A caller that reads GitHub with net/http spends from the same budget as one that uses
// go-github, from the same headers.
func TestObserveHTTPReadsTheRateHeaders(t *testing.T) {
	b := NewBudget()
	b.ObserveHTTP(response(http.StatusOK, 5000, 2501, `{}`))
	if b.Exhausted() {
		t.Fatal("2,501 of 5,000 is above half")
	}
	b.ObserveHTTP(response(http.StatusOK, 5000, 2500, `{}`))
	if !b.Exhausted() || b.Spent() != 2 {
		t.Fatalf("exhausted=%v spent=%d, want the floor reached after 2 requests", b.Exhausted(), b.Spent())
	}
}

// Keep raises the floor for a caller whose requests matter less than the token's other
// users: the licence lookups keep 80% of a job token's quota for everything else.
func TestKeepRaisesTheFloor(t *testing.T) {
	b := NewBudget(Keep(0.8), Hint("hint."))
	b.ObserveHTTP(response(http.StatusOK, 5000, 4001, `{}`))
	if b.Exhausted() {
		t.Fatal("4,001 of 5,000 is above 80%")
	}
	b.ObserveHTTP(response(http.StatusOK, 5000, 4000, `{}`))
	if !b.Exhausted() {
		t.Fatal("4,000 of 5,000 is the floor")
	}
	if r := b.Reason(); !strings.Contains(r, "4000 of 5000 requests left") || !strings.HasSuffix(r, "hint.") {
		t.Fatalf("reason %q", r)
	}
}

// A secondary rate limit answers 403 with quota still left in the headers; it stops the
// caller all the same, and says GitHub refused rather than that a floor was reached.
func TestObserveHTTPStopsOnARateLimitAnswer(t *testing.T) {
	b := NewBudget()
	b.ObserveHTTP(response(http.StatusForbidden, 5000, 4000,
		`{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again.",`+
			`"documentation_url":"https://docs.github.com/rest/overview/rate-limits-for-the-rest-api#about-secondary-rate-limits"}`))
	if !b.Exhausted() {
		t.Fatal("a secondary rate limit did not stop the budget")
	}
	if !strings.Contains(b.Reason(), "GitHub answered") {
		t.Fatalf("reason %q", b.Reason())
	}

	// A 403 that is not a rate limit is a real failure, not a reason to stop everything.
	b = NewBudget()
	b.ObserveHTTP(response(http.StatusForbidden, 5000, 4000, `{"message":"Resource not accessible by integration"}`))
	if b.Exhausted() {
		t.Fatal("a permission 403 stopped the budget")
	}
}

// Seed takes the quota from GET /rate_limit, which costs nothing: a caller that starts
// below its floor stops before its first request.
func TestSeedBelowTheFloorSpendsNothing(t *testing.T) {
	b := NewBudget(Keep(0.8))
	b.Seed(5000, 3000)
	if !b.Exhausted() || b.Spent() != 0 {
		t.Fatalf("exhausted=%v spent=%d", b.Exhausted(), b.Spent())
	}
	b = NewBudget()
	b.Seed(0, 0) // no answer: nothing known, nothing stopped
	if b.Exhausted() {
		t.Fatal("an unknown quota stopped the budget")
	}
}

func TestSpendCountsWithoutRate(t *testing.T) {
	b := NewBudget()
	b.Spend()
	b.Spend()
	if b.Spent() != 2 || b.Exhausted() {
		t.Fatalf("spent=%d exhausted=%v", b.Spent(), b.Exhausted())
	}
}
