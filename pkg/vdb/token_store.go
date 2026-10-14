package vdb

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

// The exchanged JWT is shared by every Client holding the same credentials.
//
// A scan builds several clients (quality gate, cli.sca, suppressions, insights,
// finalize) and each used to keep its own token, so one `vulnetix sca` paid for
// five /auth/token round trips before it had sent anything useful. The token is
// a function of the credentials and the endpoint, not of the client, so it is
// cached under that key: in memory for the life of the process, and on disk
// (0600, beside the response cache) so the next invocation inside the token's
// lifetime pays for none. A token the server no longer accepts costs one
// retry: a 401 on a cached token drops it and exchanges again (see
// retryUnauthorized).

// tokenRefreshMargin is how long before expiry a token stops being reused.
const tokenRefreshMargin = 3 * time.Minute

var (
	sharedTokensMu sync.Mutex
	sharedTokens   = map[string]*TokenCache{}
	// tokenStoreDir is where tokens persist; empty disables the disk store.
	// A var so tests can point it at a temporary directory.
	tokenStoreDir = defaultTokenStoreDir()
)

func defaultTokenStoreDir() string {
	if os.Getenv("VULNETIX_NO_TOKEN_CACHE") != "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vulnetix", "cache", "tokens")
}

// tokenKey identifies the credential + endpoint a token was issued for. The
// secret is hashed into it, never stored.
func (c *Client) tokenKey() string {
	h := sha256.New()
	for _, part := range []string{c.BaseURL, c.APIVersion, string(c.AuthMethod), c.OrgID, c.SecretKey} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func tokenUsable(t *TokenCache) bool {
	return t != nil && t.Token != "" && time.Now().Before(t.ExpiresAt.Add(-tokenRefreshMargin))
}

// loadSharedToken returns a usable token for key from memory, then disk.
func loadSharedToken(key string) *TokenCache {
	sharedTokensMu.Lock()
	defer sharedTokensMu.Unlock()
	if t := sharedTokens[key]; tokenUsable(t) {
		return t
	}
	if tokenStoreDir == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(tokenStoreDir, key+".json"))
	if err != nil {
		return nil
	}
	var t TokenCache
	if json.Unmarshal(raw, &t) != nil || !tokenUsable(&t) {
		return nil
	}
	sharedTokens[key] = &t
	return &t
}

// storeSharedToken records t for key in memory and, best-effort, on disk.
func storeSharedToken(key string, t *TokenCache) {
	sharedTokensMu.Lock()
	defer sharedTokensMu.Unlock()
	sharedTokens[key] = t
	if tokenStoreDir == "" {
		return
	}
	raw, err := json.Marshal(t)
	if err != nil || os.MkdirAll(tokenStoreDir, 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(tokenStoreDir, key+".*.tmp")
	if err != nil {
		return
	}
	_ = tmp.Chmod(0o600)
	_, werr := tmp.Write(raw)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), filepath.Join(tokenStoreDir, key+".json")) != nil {
		_ = os.Remove(tmp.Name())
	}
}

// dropSharedToken forgets the token for key everywhere, if it is still tok.
func dropSharedToken(key, tok string) {
	sharedTokensMu.Lock()
	defer sharedTokensMu.Unlock()
	if t := sharedTokens[key]; t != nil && t.Token == tok {
		delete(sharedTokens, key)
	}
	if tokenStoreDir == "" {
		return
	}
	path := filepath.Join(tokenStoreDir, key+".json")
	if raw, err := os.ReadFile(path); err == nil {
		var t TokenCache
		if json.Unmarshal(raw, &t) == nil && t.Token == tok {
			_ = os.Remove(path)
		}
	}
}

// retryUnauthorized reports whether a 401 should be retried with a freshly
// exchanged token, and if so re-authorizes req. It fires at most once per
// request (tracked by *retried) and only for the exchanged-JWT auth method,
// where the token may simply be one the server has stopped accepting.
func (c *Client) retryUnauthorized(req *http.Request, status int, retried *bool) bool {
	if status != http.StatusUnauthorized || *retried || c.AuthMethod == auth.Token || c.AuthMethod == auth.DirectAPIKey {
		return false
	}
	*retried = true
	c.tokenMutex.Lock()
	stale := c.token
	c.token = nil
	c.tokenMutex.Unlock()
	if stale != nil {
		dropSharedToken(c.tokenKey(), stale.Token)
	}
	return c.addAuthHeader(req) == nil
}
