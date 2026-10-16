package svc

import "go.uber.org/zap"

type Config struct{ DSN, APIToken string }

func show(logger *zap.SugaredLogger, cfg Config) {
~>	logger.Infof("config loaded: dsn=%s token=%s",
		cfg.DSN,
		cfg.APIToken)
}
