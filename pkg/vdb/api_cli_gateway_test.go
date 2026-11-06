package vdb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulnetix/cli/v4/pkg/auth"
)

const gatewayPage = `<!DOCTYPE HTML><html><head><title>ERROR: The request could not be satisfied</title></head><body>504 Gateway Time-out</body></html>`

func gatewayTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	old := gatewayBackoff
	gatewayBackoff = time.Millisecond
	t.Cleanup(func() { gatewayBackoff = old })
	c := NewClientFromCredentials(&auth.Credentials{OrgID: "00000000-0000-0000-0000-000000000000", APIKey: "k", Method: auth.DirectAPIKey})
	c.BaseURL = srv.URL
	c.APIVersion = "/v2"
	c.Cache = nil

	return c, &calls
}

// The edge answers with its own error page before a request reaches the API.
// That request can be sent again without recording anything twice, so one such
// answer must not fail a whole upload.
func TestGatewayErrorPageIsRetried(t *testing.T) {
	var n atomic.Int64
	c, calls := gatewayTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = w.Write([]byte(gatewayPage))

			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"data":{}}`))
	})
	if _, err := cliPostWithEnvContext[map[string]any](context.Background(), c, "cli.ping", CliEnv{}, map[string]string{"a": "b"}); err != nil {
		t.Fatalf("a request that succeeded on the third attempt failed: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("server saw %d requests, want 3", got)
	}
}

// A 504 the API wrote itself (JSON) may have acted on the request, so it is not
// repeated: that would risk recording the upload twice.
func TestAPIWrittenServerErrorIsNotRetried(t *testing.T) {
	c, calls := gatewayTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = w.Write([]byte(`{"error":"upstream timed out"}`))
	})
	_, err := cliPostWithEnvContext[map[string]any](context.Background(), c, "cli.ping", CliEnv{}, map[string]string{"a": "b"})
	var apiErr *CliAPIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("err = %v, want a CliAPIError with status 504", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("server saw %d requests, want 1: an error the API wrote must not be repeated", got)
	}
}

// Retries are bounded, and the error that comes back still says the gateway
// answered, so the message is the same one a user saw before.
func TestGatewayRetriesAreBounded(t *testing.T) {
	c, calls := gatewayTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(gatewayPage))
	})
	_, err := cliPostWithEnvContext[map[string]any](context.Background(), c, "cli.ping", CliEnv{}, map[string]string{"a": "b"})
	var apiErr *CliAPIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("err = %v, want a CliAPIError with status 502", err)
	}
	if got := calls.Load(); got != gatewayRetries+1 {
		t.Fatalf("server saw %d requests, want %d", got, gatewayRetries+1)
	}
}

func TestGatewayRetryStopsWhenTheContextEnds(t *testing.T) {
	c, _ := gatewayTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(gatewayPage))
	})
	gatewayBackoff = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := cliPostWithEnvContext[map[string]any](ctx, c, "cli.ping", CliEnv{}, map[string]string{"a": "b"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context's deadline", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the retry wait did not end with the context")
	}
}
