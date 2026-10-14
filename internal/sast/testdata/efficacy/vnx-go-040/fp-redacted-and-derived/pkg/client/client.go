package client

import (
	"log"
	"log/slog"

	"go.uber.org/zap"
)

func (c *Client) audit(logger *zap.Logger, password, token, cardNumber string) {
	logger.Info("login", zap.String("password", "[REDACTED]"))
	slog.Info("issued", "token", redact(token))
	log.Printf("password length %d", len(password))
	log.Printf("card %s", mask(cardNumber))
	log.Printf("token fingerprint %s", fingerprint(token))
	slog.Info("auth", slog.Bool("hasPassword", c.hasPassword), "keyID", c.keyID)
	log.Printf("secret %s rotated", c.secretName)
}
