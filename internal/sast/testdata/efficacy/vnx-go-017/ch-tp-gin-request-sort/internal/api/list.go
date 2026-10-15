package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Handler struct{ db *gorm.DB }

func (h *Handler) List(c *gin.Context) {
	var rows []map[string]any
	sort := c.Request.URL.Query().Get("sort")
~>	q := fmt.Sprintf("SELECT id, name FROM products ORDER BY %s", sort)
	h.db.Raw(q).Scan(&rows)
	c.JSON(http.StatusOK, rows)
}
