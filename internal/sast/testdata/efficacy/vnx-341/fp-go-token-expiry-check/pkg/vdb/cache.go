package vdb

import "time"

type TokenCache struct {
	Token     string
	ExpiresAt time.Time
}

const tokenRefreshMargin = 30 * time.Second

// A yes/no answer about a cached token: the clock decides whether it is
// still usable, it does not produce the token.
func tokenUsable(t *TokenCache) bool {
	return t != nil && t.Token != "" && time.Now().Before(t.ExpiresAt.Add(-tokenRefreshMargin))
}

func tokenExpired(t *TokenCache) bool {
	return time.Now().After(t.ExpiresAt)
}
