package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// deviceServer is a fake www.vulnetix.com implementing RFC 8628.
type deviceServer struct {
	mu sync.Mutex

	// tokenReplies is consumed one entry per /token poll. The last entry
	// repeats once exhausted.
	tokenReplies []tokenReply

	// pollTimes records when each /token request arrived, so a test can assert
	// the client actually backed off.
	pollTimes []time.Time

	// expiresIn is the grant TTL advertised by /authorize, in seconds.
	// Defaults to 5, enough for several 1s polls.
	expiresIn int

	// authorizeStatus and authorizeBody override the /authorize response.
	authorizeStatus int
	authorizeBody   any
}

type tokenReply struct {
	status int
	body   map[string]string
}

func (s *deviceServer) start(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/site/v1/cli/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		status := s.authorizeStatus
		if status == 0 {
			status = http.StatusOK
		}

		expiresIn := s.expiresIn
		if expiresIn == 0 {
			expiresIn = 5
		}

		var body any = map[string]any{
			"device_code":               "secret-device-code",
			"user_code":                 "ABC-123",
			"verification_uri":          "https://example.test/cli-login-code",
			"verification_uri_complete": "https://example.test/cli-login-code?user_code=ABC-123",
			"expires_in":                expiresIn,
			"interval":                  1,
		}
		if s.authorizeBody != nil {
			body = s.authorizeBody
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("/api/site/v1/cli/device/token", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.pollTimes = append(s.pollTimes, time.Now())

		var req struct {
			DeviceCode string `json:"device_code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		i := len(s.pollTimes) - 1
		if i >= len(s.tokenReplies) {
			i = len(s.tokenReplies) - 1
		}
		reply := s.tokenReplies[i]
		s.mu.Unlock()

		if req.DeviceCode != "secret-device-code" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(reply.status)
		_ = json.NewEncoder(w).Encode(reply.body)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv("VULNETIX_WEB_URL", srv.URL)

	return srv
}

func (s *deviceServer) polls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.pollTimes)
}

func okReply() tokenReply {
	return tokenReply{http.StatusOK, map[string]string{
		"orgId":  "11111111-2222-3333-4444-555555555555",
		"apiKey": "11111111-2222-3333-4444-555555555555:deadbeefcafe",
	}}
}

func errReply(code string) tokenReply {
	return tokenReply{http.StatusBadRequest, map[string]string{"error": code}}
}

func TestDeviceFlowWebBaseURL(t *testing.T) {
	t.Setenv("VULNETIX_WEB_URL", "")
	if got := webBaseURL(); got != defaultWebURL {
		t.Errorf("webBaseURL() = %q, want %q", got, defaultWebURL)
	}
	if got := deviceAPIBase(); got != defaultWebURL+"/api/site/v1/cli/device" {
		t.Errorf("deviceAPIBase() = %q", got)
	}

	// The override wins, and a trailing slash is trimmed so paths do not double up.
	t.Setenv("VULNETIX_WEB_URL", "http://localhost:5173/")
	if got := webBaseURL(); got != "http://localhost:5173" {
		t.Errorf("webBaseURL() = %q, want the trimmed override", got)
	}
	if got := deviceAPIBase(); got != "http://localhost:5173/api/site/v1/cli/device" {
		t.Errorf("deviceAPIBase() = %q", got)
	}
}

func TestDeviceFlowAuthorize(t *testing.T) {
	s := &deviceServer{tokenReplies: []tokenReply{okReply()}}
	s.start(t)

	da, err := deviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("deviceAuthorize() error: %v", err)
	}
	if da.DeviceCode != "secret-device-code" || da.UserCode != "ABC-123" {
		t.Fatalf("deviceAuthorize() = %+v", da)
	}
	if da.interval() != time.Second {
		t.Errorf("interval() = %v, want 1s", da.interval())
	}
	if da.expiry() != 5*time.Second {
		t.Errorf("expiry() = %v, want 5s", da.expiry())
	}
	// The CLI opens the code-carrying URL so the user need not retype.
	if da.browseURL() != da.VerificationURIComplete {
		t.Errorf("browseURL() = %q, want the complete URI", da.browseURL())
	}
}

func TestDeviceFlowAuthorizeDefaultsWhenServerOmitsTimings(t *testing.T) {
	s := &deviceServer{
		tokenReplies: []tokenReply{okReply()},
		authorizeBody: map[string]any{
			"device_code":      "secret-device-code",
			"user_code":        "ABC-123",
			"verification_uri": "https://example.test/cli-login-code",
		},
	}
	s.start(t)

	da, err := deviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("deviceAuthorize() error: %v", err)
	}
	if da.interval() != devicePollInterval {
		t.Errorf("interval() = %v, want the %v default", da.interval(), devicePollInterval)
	}
	if da.expiry() != devicePollTimeout {
		t.Errorf("expiry() = %v, want the %v default", da.expiry(), devicePollTimeout)
	}
	// With no complete URI, fall back to the plain verification URI.
	if da.browseURL() != da.VerificationURI {
		t.Errorf("browseURL() = %q, want the plain URI", da.browseURL())
	}
}

func TestDeviceFlowAuthorizeRejected(t *testing.T) {
	s := &deviceServer{
		tokenReplies:    []tokenReply{okReply()},
		authorizeStatus: http.StatusTooManyRequests,
		authorizeBody:   map[string]string{"error": "slow_down"},
	}
	s.start(t)

	if _, err := deviceAuthorize(context.Background()); err == nil {
		t.Fatal("deviceAuthorize() succeeded on HTTP 429, want an error")
	}
}

func TestDeviceFlowAuthorizeIncompleteResponse(t *testing.T) {
	s := &deviceServer{
		tokenReplies:  []tokenReply{okReply()},
		authorizeBody: map[string]any{"user_code": "ABC-123"},
	}
	s.start(t)

	if _, err := deviceAuthorize(context.Background()); err == nil {
		t.Fatal("deviceAuthorize() succeeded without a device_code, want an error")
	}
}

func TestDeviceFlowPollSucceedsImmediately(t *testing.T) {
	s := &deviceServer{tokenReplies: []tokenReply{okReply()}}
	s.start(t)

	da, err := deviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("deviceAuthorize() error: %v", err)
	}

	orgID, apiKey, err := pollForToken(da)
	if err != nil {
		t.Fatalf("pollForToken() error: %v", err)
	}
	if orgID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("orgID = %q", orgID)
	}
	if apiKey != orgID+":deadbeefcafe" {
		t.Errorf("apiKey = %q", apiKey)
	}
}

func TestDeviceFlowPollWaitsThroughAuthorizationPending(t *testing.T) {
	s := &deviceServer{tokenReplies: []tokenReply{
		errReply("authorization_pending"),
		errReply("authorization_pending"),
		okReply(),
	}}
	s.start(t)

	da, err := deviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("deviceAuthorize() error: %v", err)
	}

	if _, _, err := pollForToken(da); err != nil {
		t.Fatalf("pollForToken() error: %v", err)
	}
	if got := s.polls(); got != 3 {
		t.Errorf("polled %d times, want 3 (two pending, then success)", got)
	}
}

func TestDeviceFlowPollBacksOffOnSlowDown(t *testing.T) {
	// Shrink the bump so the assertion is observable without a slow test.
	orig := deviceSlowDownBump
	deviceSlowDownBump = 400 * time.Millisecond
	t.Cleanup(func() { deviceSlowDownBump = orig })

	s := &deviceServer{tokenReplies: []tokenReply{
		errReply("slow_down"),
		okReply(),
	}}
	s.start(t)

	da, err := deviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("deviceAuthorize() error: %v", err)
	}

	if _, _, err := pollForToken(da); err != nil {
		t.Fatalf("pollForToken() error: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.pollTimes) != 2 {
		t.Fatalf("polled %d times, want 2", len(s.pollTimes))
	}

	gap := s.pollTimes[1].Sub(s.pollTimes[0])
	want := da.interval() + deviceSlowDownBump
	if gap < want-100*time.Millisecond {
		t.Errorf("second poll came after %v, want at least the backed-off interval %v", gap, want)
	}
}

func TestDeviceFlowPollBacksOffOnRateLimit(t *testing.T) {
	orig := deviceSlowDownBump
	deviceSlowDownBump = 400 * time.Millisecond
	t.Cleanup(func() { deviceSlowDownBump = orig })

	// A 429 from the rate limiter carries no RFC 8628 error code, but must
	// still back the client off rather than hammer.
	s := &deviceServer{tokenReplies: []tokenReply{
		{http.StatusTooManyRequests, map[string]string{}},
		okReply(),
	}}
	s.start(t)

	da, err := deviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("deviceAuthorize() error: %v", err)
	}

	if _, _, err := pollForToken(da); err != nil {
		t.Fatalf("pollForToken() error: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	gap := s.pollTimes[1].Sub(s.pollTimes[0])
	want := da.interval() + deviceSlowDownBump
	if gap < want-100*time.Millisecond {
		t.Errorf("second poll came after %v, want at least %v", gap, want)
	}
}

func TestDeviceFlowPollExpiredToken(t *testing.T) {
	s := &deviceServer{tokenReplies: []tokenReply{errReply("expired_token")}}
	s.start(t)

	da, err := deviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("deviceAuthorize() error: %v", err)
	}

	_, _, err = pollForToken(da)
	if err != errDeviceExpired {
		t.Fatalf("pollForToken() error = %v, want errDeviceExpired", err)
	}
}

func TestDeviceFlowPollAccessDeniedIsNotRetryable(t *testing.T) {
	s := &deviceServer{tokenReplies: []tokenReply{errReply("access_denied")}}
	s.start(t)

	da, err := deviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("deviceAuthorize() error: %v", err)
	}

	_, _, err = pollForToken(da)
	if err == nil {
		t.Fatal("pollForToken() succeeded on access_denied")
	}
	// browserLogin only offers a retry for errDeviceExpired; a denial must not
	// masquerade as an expiry.
	if err == errDeviceExpired {
		t.Fatal("access_denied surfaced as errDeviceExpired, would trigger a retry prompt")
	}
}

func TestDeviceFlowPollTimesOutWhileStillPending(t *testing.T) {
	// authorize advertises expires_in=2; the server never approves.
	s := &deviceServer{
		expiresIn:    2,
		tokenReplies: []tokenReply{errReply("authorization_pending")},
	}
	s.start(t)

	da, err := deviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("deviceAuthorize() error: %v", err)
	}

	start := time.Now()

	_, _, err = pollForToken(da)
	if err != errDeviceExpired {
		t.Fatalf("pollForToken() error = %v, want errDeviceExpired", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("pollForToken() ran %v, expected to stop near the 2s expires_in", elapsed)
	}
}

func TestDeviceFlowPollKeepsTryingThroughTransportErrors(t *testing.T) {
	// The server 500s once with a body the client cannot decode, then succeeds.
	// A transport hiccup must not abort the grant.
	var polls int
	mux := http.NewServeMux()

	mux.HandleFunc("/api/site/v1/cli/device/token", func(w http.ResponseWriter, r *http.Request) {
		polls++
		if polls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("<html>gateway timeout</html>"))

			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(okReply().body)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv("VULNETIX_WEB_URL", srv.URL)

	da := &deviceAuth{DeviceCode: "secret-device-code", ExpiresIn: 4, Interval: 1}

	orgID, _, err := pollForToken(da)
	if err != nil {
		t.Fatalf("pollForToken() error: %v", err)
	}
	if orgID == "" {
		t.Error("expected an orgID after recovering from the 502")
	}
	if polls != 2 {
		t.Errorf("polled %d times, want 2", polls)
	}
}
