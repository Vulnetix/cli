package db

import (
	"log/slog"
)

func Open(cfg Config) {
~>	slog.Info("opening database", "user", cfg.User, "password", cfg.Password)
}
