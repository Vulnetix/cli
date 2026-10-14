package client

import "log/slog"

func presence(logger *slog.Logger, apiKey, token string) {
	logger.Info("fetching",
		"hasAPIKey", apiKey != "",
	)
	logger.Warn("disabled", "haveToken", token != "", "empty", "" == token)
}
