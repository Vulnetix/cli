package api

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func Export(c *gin.Context) {
	target := c.Request.FormValue("dest")
~>	f, err := os.Create("/srv/exports/" + target)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer f.Close()
	f.WriteString("ok")
}
