package client

import (
	"log/slog"

	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

func (c *Client) connect(logger *zap.Logger, apiKey, pw string) {
~>	logger.Info("connecting", zap.String("api_key", apiKey))
~>	slog.Info("login", "user", c.user, "password", pw)
~>	logrus.WithField("token", c.cfg.Token).Info("refreshing")
~>	log.Debug().Str("secret", c.signingSecret).Msg("loaded")
~>	logrus.WithFields(logrus.Fields{"user": c.user, "private_key": c.pem}).Warn("rotating")
}
