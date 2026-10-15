package api

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Lookup(c *gin.Context) {
	host := c.Query("host")
~>	out, _ := exec.Command(
		"sh", "-c",
		"nslookup "+host,
	).CombinedOutput()
	c.String(http.StatusOK, string(out))
}

func Next(c *gin.Context) {
	next := c.Request.URL.Query().Get("next")
~>	http.Redirect(c.Writer, c.Request, next, http.StatusFound)
}
