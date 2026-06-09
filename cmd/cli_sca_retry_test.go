package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// testSCAClient builds a vdb.Client pointed at a test server. It uses DirectAPIKey
// auth so addAuthHeader signs inline (no separate token-exchange round-trip that
// would otherwise hit the test handler and skew request counts).
func testSCAClient(url string) *vdb.Client {
	c := vdb.NewClient("org", "secret")
	c.BaseURL = url
	c.APIVersion = "/v2"
	c.AuthMethod = auth.DirectAPIKey
	c.APIKey = "deadbeef"
	return c
}

// shrinkBackoff makes the retry/backoff knobs tiny so tests run fast, restoring
// the production values afterwards.
func shrinkBackoff(t *testing.T) {
	t.Helper()
	ob, om, oa := scaBackoffBase, scaBackoffMax, maxBatchAttempts
	scaBackoffBase, scaBackoffMax, maxBatchAttempts = time.Millisecond, 2*time.Millisecond, 3
	t.Cleanup(func() { scaBackoffBase, scaBackoffMax, maxBatchAttempts = ob, om, oa })
}

const scaOKBody = `{"meta":{"tier":"community"},"data":{"cyclonedx":{"components":[],"vulnerabilities":[]}}}`

// reqPurls decodes the PURLs the server received for a cli.sca request.
func reqPurls(r *http.Request) []string {
	var body struct {
		Payload struct {
			Purls []string `json:"purls"`
		} `json:"payload"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	return body.Payload.Purls
}

func TestIsRetryableCliErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"429", &vdb.CliAPIError{StatusCode: 429}, true},
		{"500", &vdb.CliAPIError{StatusCode: 500}, true},
		{"503", &vdb.CliAPIError{StatusCode: 503}, true},
		{"400", &vdb.CliAPIError{StatusCode: 400}, false},
		{"401", &vdb.CliAPIError{StatusCode: 401}, false},
		{"403", &vdb.CliAPIError{StatusCode: 403}, false},
		{"404", &vdb.NotFoundError{Message: "nope"}, false},
		{"deadline", context.DeadlineExceeded, true},
		{"transport", &wrapErr{msg: "cli.sca: failed to execute request: dial tcp: timeout"}, true},
		{"decode", &wrapErr{msg: "decode envelope: unexpected EOF"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableCliErr(tc.err); got != tc.want {
				t.Fatalf("isRetryableCliErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

type wrapErr struct{ msg string }

func (e *wrapErr) Error() string { return e.msg }

func TestBackoffDelay(t *testing.T) {
	ob, om := scaBackoffBase, scaBackoffMax
	scaBackoffBase, scaBackoffMax = 100*time.Millisecond, time.Second
	defer func() { scaBackoffBase, scaBackoffMax = ob, om }()

	// Retry-After wins, capped at the ceiling.
	if d := backoffDelay(1, &vdb.CliAPIError{StatusCode: 429, RetryAfter: 50 * time.Millisecond}); d != 50*time.Millisecond {
		t.Fatalf("Retry-After honoured: got %v", d)
	}
	if d := backoffDelay(1, &vdb.CliAPIError{StatusCode: 429, RetryAfter: 10 * time.Second}); d != scaBackoffMax {
		t.Fatalf("Retry-After cap: got %v want %v", d, scaBackoffMax)
	}
	// Exponential growth, capped.
	d1 := backoffDelay(1, &wrapErr{msg: "x"})
	d2 := backoffDelay(2, &wrapErr{msg: "x"})
	if d2 <= d1 {
		t.Fatalf("expected exponential growth: d1=%v d2=%v", d1, d2)
	}
	if d := backoffDelay(10, &wrapErr{msg: "x"}); d > scaBackoffMax+scaBackoffBase {
		t.Fatalf("expected capped near ceiling: got %v", d)
	}
}

func TestSplitPurls(t *testing.T) {
	a, b := splitPurls([]string{"1", "2", "3", "4"})
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("even split: %v %v", a, b)
	}
	a, b = splitPurls([]string{"1", "2", "3"})
	if len(a) != 1 || len(b) != 2 {
		t.Fatalf("odd split: %v %v", a, b)
	}
	a, b = splitPurls([]string{"x", "y"})
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("min split: %v %v", a, b)
	}
}

func TestSendCliSCAWithRetry_RetriesThenSucceeds(t *testing.T) {
	shrinkBackoff(t)
	var attempts int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"transient"}`))
			return
		}
		_, _ = w.Write([]byte(scaOKBody))
	}))
	defer srv.Close()

	client := testSCAClient(srv.URL)
	_, err := sendCliSCAWithRetry(client, vdb.CliEnv{}, vdb.CliSCARequest{Purls: []string{"pkg:npm/a@1"}}, "test", io.Discard)
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestSendCliSCAWithRetry_429RetryAfter(t *testing.T) {
	shrinkBackoff(t)
	var attempts int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n == 1 {
			w.Header().Set("Retry-After", "1") // capped to scaBackoffMax in test
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		_, _ = w.Write([]byte(scaOKBody))
	}))
	defer srv.Close()

	client := testSCAClient(srv.URL)
	_, err := sendCliSCAWithRetry(client, vdb.CliEnv{}, vdb.CliSCARequest{Purls: []string{"pkg:npm/a@1"}}, "test", io.Discard)
	if err != nil {
		t.Fatalf("expected success after 429 retry, got %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestSendCliSCAWithRetry_401Terminal(t *testing.T) {
	shrinkBackoff(t)
	var attempts int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()

	client := testSCAClient(srv.URL)
	_, err := sendCliSCAWithRetry(client, vdb.CliEnv{}, vdb.CliSCARequest{Purls: []string{"pkg:npm/a@1"}}, "test", io.Discard)
	if err == nil {
		t.Fatal("expected terminal error on 401")
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 attempt (no retry on 401), got %d", attempts)
	}
}

// TestRunSCAJobs_SubChunkSplit emulates a vuln-dense chunk that fails until it is
// small enough: the server 503s any multi-PURL request and 200s singletons. The
// engine must split the chunk down to singletons and cover every package, with
// no unservable PURLs and no legacy fallback.
func TestRunSCAJobs_SubChunkSplit(t *testing.T) {
	shrinkBackoff(t)
	var mu sync.Mutex
	var singletonOK int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		purls := reqPurls(r)
		if len(purls) > 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"too big"}`))
			return
		}
		mu.Lock()
		singletonOK++
		mu.Unlock()
		_, _ = w.Write([]byte(scaOKBody))
	}))
	defer srv.Close()

	client := testSCAClient(srv.URL)
	jobs := []scaJob{{purls: []string{"a", "b", "c", "d"}, manifestSlot: -1}}
	buildReq := func(job scaJob) (vdb.CliEnv, vdb.CliSCARequest, bool) {
		return vdb.CliEnv{}, vdb.CliSCARequest{Purls: job.purls}, false
	}
	onResult := func(_ scaJob, _ *vdb.CliResponse[vdb.CliSCAResponse]) {}

	unservable, anyOK, _ := runSCAJobs(client, jobs, buildReq, onResult, io.Discard)
	if !anyOK {
		t.Fatal("expected anyOK after splitting")
	}
	if len(unservable) != 0 {
		t.Fatalf("expected no unservable, got %v", unservable)
	}
	if singletonOK != 4 {
		t.Fatalf("expected 4 singleton successes, got %d", singletonOK)
	}
}

// TestRunSCAJobs_Unservable: when the server fails every request, splitting bottoms
// out at single PURLs which are recorded as unservable — never sent to a legacy path.
func TestRunSCAJobs_Unservable(t *testing.T) {
	shrinkBackoff(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"down"}`))
	}))
	defer srv.Close()

	client := testSCAClient(srv.URL)
	jobs := []scaJob{{purls: []string{"a", "b"}, manifestSlot: -1}}
	buildReq := func(job scaJob) (vdb.CliEnv, vdb.CliSCARequest, bool) {
		return vdb.CliEnv{}, vdb.CliSCARequest{Purls: job.purls}, false
	}
	onResult := func(_ scaJob, _ *vdb.CliResponse[vdb.CliSCAResponse]) {}

	unservable, anyOK, firstErr := runSCAJobs(client, jobs, buildReq, onResult, io.Discard)
	if anyOK {
		t.Fatal("expected anyOK=false when every request fails")
	}
	if firstErr == nil {
		t.Fatal("expected firstErr to be set")
	}
	if len(unservable) != 2 {
		t.Fatalf("expected 2 unservable PURLs, got %v", unservable)
	}
}
