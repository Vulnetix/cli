package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Password string `json:"-"`
}

func (h *Handler) GetUser(c *gin.Context) {
	var user User
	h.db.First(&user, c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"id": user.ID, "name": user.Name, "passwordSet": user.Password != ""})
}
