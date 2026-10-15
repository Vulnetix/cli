package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
)

func (h *Handler) callback(c echo.Context) error {
	accessToken, err := h.exchange(c.QueryParam("code"))
	if err != nil {
		return err
	}
~>	c.Logger().Infof("exchanged code for %s", accessToken)
~>	log.Ctx(c.Request().Context()).Debug().Str("access_token", accessToken).Msg("oauth ok")
	return c.NoContent(http.StatusOK)
}

func (h *Handler) debug(lg *zap.Logger, apiKey string) {
~>	lg.Sugar().Debugf("calling upstream with key %s", apiKey)
}
