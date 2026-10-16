package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetAccount(c *gin.Context) {
	acct, err := h.store.AccountByID(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":    acct.ID,
		"email": acct.Email,
~>		"secret": acct.Secret,
	})
}
