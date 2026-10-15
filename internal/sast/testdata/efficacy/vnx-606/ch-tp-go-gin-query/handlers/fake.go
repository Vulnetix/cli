package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func Generate(c *gin.Context) {
	count, err := strconv.Atoi(c.DefaultQuery("count", "10"))
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	items := make([]string, 0)
~>	for i := 0; i < count; i++ {
		items = append(items, strconv.Itoa(i))
	}
	c.JSON(http.StatusOK, items)
}
