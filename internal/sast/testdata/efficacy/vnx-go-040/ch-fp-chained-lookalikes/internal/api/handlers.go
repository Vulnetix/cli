package api

import (
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
)

func (h *Handler) callback(c echo.Context, tokenURL string, tokens []string) {
	c.Logger().Infof("exchanging code at %s", tokenURL)
	log.Ctx(c.Request().Context()).Debug().Int("tokens", len(tokens)).Msg("oauth ok")
	h.lg.Sugar().Infof("password reset email sent to %s", c.QueryParam("email"))
	h.lg.Named("auth").Info("token refreshed", zap.String("user", h.user))
}
