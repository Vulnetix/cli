package web

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Search(c *gin.Context) {
	var q SearchQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		return
	}
	c.JSON(200, run(q))
}

func Proxy(w http.ResponseWriter, resp *http.Response) {
	var out Payload
	_ = json.NewDecoder(resp.Body).Decode(&out)
	cache.Save(&out)
}

// Bind with c.ShouldBindJSON(&u) and then db.Create(&u) is mass assignment.
const note = "c.ShouldBindJSON(&u); db.Create(&u)"
