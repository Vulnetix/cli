package svc

import (
	"log/slog"

	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

func connect(logger *zap.Logger, apiKey string, pw string, cfg struct{ Token string }) {
~>	logger.Info("connecting", zap.String("api_key", apiKey))
~>	slog.Info("login", "user", "bob", "password", pw)
~>	logrus.WithField("token", cfg.Token).Info("refreshing")
}
