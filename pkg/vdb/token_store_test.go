package vdb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

func TestMain(m *testing.M) {
	// Never let a test write tokens into the developer's real ~/.vulnetix.
	dir, err := os.MkdirTemp("", "vdb-tokens-")
	if err != nil {
		panic(err)
	}
	tokenStoreDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// tokenServer issues a new token per exchange (tok-1, tok-2, ...), rejects
// tokens listed in revoked with a 401, and counts exchanges.
type tokenServer struct {
	*httptest.Server
	exchanges atomic.Int64
	revoked   atomic.Value // string: a token the server no longer accepts
}

func newTokenServer(t *testing.T) *tokenServer {
	ts := &tokenServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/auth/token" {
			n := ts.exchanges.Add(1)
			_ = json.NewEncoder(w).Encode(TokenResponse{Token: fmt.Sprintf("tok-%d", n), Exp: time.Now().Add(15 * time.Minute).Unix()})
			return
		}
		if rv, _ := ts.revoked.Load().(string); rv != "" && r.Header.Get("Authorization") == "Bearer "+rv {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func sigv4Client(baseURL, secret string) *Client {
	c := NewClientFromCredentials(&auth.Credentials{OrgID: "11111111-1111-1111-1111-111111111111", Secret: secret, Method: auth.SigV4})
	c.BaseURL = baseURL
	return c
}

func resetMemoryTokens() {
	sharedTokensMu.Lock()
	sharedTokens = map[string]*TokenCache{}
	sharedTokensMu.Unlock()
}

func TestTokenSharedAcrossClients(t *testing.T) {
	ts := newTokenServer(t)
	for i := 0; i < 5; i++ {
		if _, err := sigv4Client(ts.URL, "s3cret").DoRequest("GET", "/ping", nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := ts.exchanges.Load(); n != 1 {
		t.Fatalf("five clients with one credential exchanged %d tokens, want 1", n)
	}
}

func TestTokenPersistsAcrossProcesses(t *testing.T) {
	ts := newTokenServer(t)
	c := sigv4Client(ts.URL, "s3cret")
	if _, err := c.GetToken(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(tokenStoreDir, c.tokenKey()+".json"))
	if err != nil {
		t.Fatalf("token not persisted: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("token file mode %o, want 600", perm)
	}

	resetMemoryTokens() // a new invocation starts with nothing in memory
	if _, err := sigv4Client(ts.URL, "s3cret").DoRequest("GET", "/ping", nil); err != nil {
		t.Fatal(err)
	}
	if n := ts.exchanges.Load(); n != 1 {
		t.Fatalf("second invocation exchanged again (%d exchanges), want the persisted token reused", n)
	}
}

func TestTokenKeyedByCredential(t *testing.T) {
	ts := newTokenServer(t)
	a, _ := sigv4Client(ts.URL, "secret-a").GetToken()
	b, _ := sigv4Client(ts.URL, "secret-b").GetToken()
	if a == b || ts.exchanges.Load() != 2 {
		t.Fatalf("different secrets shared a token (a=%q b=%q exchanges=%d)", a, b, ts.exchanges.Load())
	}
	raw, _ := os.ReadFile(filepath.Join(tokenStoreDir, sigv4Client(ts.URL, "secret-a").tokenKey()+".json"))
	if len(raw) == 0 || !json.Valid(raw) {
		t.Fatalf("persisted token is not JSON: %q", raw)
	}
	for _, s := range []string{"secret-a", "secret-b"} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("persisted token file contains the secret %q", s)
		}
	}
}

func TestRejectedCachedTokenIsExchangedOnce(t *testing.T) {
	ts := newTokenServer(t)
	if _, err := sigv4Client(ts.URL, "s3cret").GetToken(); err != nil {
		t.Fatal(err)
	}
	// The server stops accepting tok-1 (say, its signing key rotated).
	ts.revoked.Store("tok-1")

	for _, call := range []func(*Client) error{
		func(c *Client) error { _, err := c.DoRequest("POST", "/ping", map[string]string{"a": "b"}); return err },
		func(c *Client) error {
			_, err := cliPostWithEnvContext[map[string]any](nil, c, "cli.ping", CliEnv{}, map[string]string{"a": "b"})
			return err
		},
	} {
		resetMemoryTokens()
		_ = os.RemoveAll(tokenStoreDir)
		storeSharedToken(sigv4Client(ts.URL, "s3cret").tokenKey(), &TokenCache{Token: "tok-1", ExpiresAt: time.Now().Add(time.Hour)})
		before := ts.exchanges.Load()
		if err := call(sigv4Client(ts.URL, "s3cret")); err != nil {
			t.Fatalf("request with a rejected cached token failed instead of re-exchanging: %v", err)
		}
		if got := ts.exchanges.Load() - before; got != 1 {
			t.Fatalf("re-exchanged %d times, want 1", got)
		}
	}
}
