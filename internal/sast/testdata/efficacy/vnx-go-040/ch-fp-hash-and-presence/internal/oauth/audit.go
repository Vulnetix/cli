package oauth

import (
	"crypto/sha256"
	"encoding/hex"

	"go.uber.org/zap"
)

func fingerprint(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

func (c *Client) audit(tok Token) {
	c.log.Info("token issued",
		zap.String("token_fingerprint", fingerprint(tok.Access)),
		zap.Time("expires", tok.Expiry),
	)
	c.log.Debug("password policy", zap.Int("password_min_length", c.policy.MinLength))
}
