package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Proxy(c *gin.Context) {
	host := c.Param("host")
~>	resp, _ := http.Get("http://" + host + "/status")
	_ = resp
}
