package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Account struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"`
	APIKey   string `json:"-"`
}

func (h *Handler) GetAccount(c *gin.Context) {
	acct, err := h.store.AccountByID(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, acct)
}
