package authz

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) Logout(c *gin.Context) {
	redirectURL := c.Query("post_logout_redirect_uri")
	if err := h.registry.CheckRedirect(c.Query("client_id"), redirectURL); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.Redirect(http.StatusFound, redirectURL)
}

func (h *Handler) Done(c *gin.Context) {
	cb := c.Query("callback_url")
	switch cb {
	case h.cfg.WebCallback, h.cfg.MobileCallback:
	default:
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.Redirect(http.StatusFound, cb)
}
