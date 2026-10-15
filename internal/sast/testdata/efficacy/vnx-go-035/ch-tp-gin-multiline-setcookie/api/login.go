package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) login(c *gin.Context) {
	token, err := s.auth.Login(c.PostForm("user"), c.PostForm("pass"))
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
~>	c.SetCookie(
		"access_token",
		token,
		int(s.ttl.Seconds()),
		"/",
		s.cfg.Domain,
		true,
		false,
	)
	c.Status(http.StatusNoContent)
}
