package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetUser(c *gin.Context) {
	u, err := h.store.FindUser(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
~>	c.JSON(http.StatusOK, gin.H{"name": u.Name, "password": u.Password})
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	acct := h.store.Account(r.URL.Query().Get("id"))
~>	json.NewEncoder(w).Encode(map[string]string{"user": acct.Name, "secret": acct.APIKey})
}
