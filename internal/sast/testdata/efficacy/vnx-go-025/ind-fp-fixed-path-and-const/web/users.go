package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func ShowUser(c *gin.Context) {
	id := c.Param("id")
	c.Redirect(http.StatusFound, "/users/"+id+"/profile")
}

func Home(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://app.example.com/", http.StatusFound)
}
