package auth

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

func (h *Handler) issueRefresh(c echo.Context, tok string) {
~>	ck := &http.Cookie{}
	ck.Name = "refresh_token"
	ck.Value = tok
	ck.Path = "/auth/refresh"
	ck.Secure = true
	ck.Expires = time.Now().Add(14 * 24 * time.Hour)
	c.SetCookie(ck)
}
