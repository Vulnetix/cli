package svc

import (
	"log/slog"

	"go.uber.org/zap"
)

func redact(s string) string { return "***" }

func f(l *zap.Logger, token, apiKey, cardNumber string) {
	l.Info("auth", zap.String("password", "[REDACTED]"))
	slog.Info("token", "value", redact(token))
	slog.Info("cfg", "hasAPIKey", apiKey != "")
	slog.Info("card", "masked", redact(cardNumber))
}
