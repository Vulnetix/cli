package web

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

func GinSearch(c *gin.Context) {
	c.Header("Content-Type", "text/html")
~>	fmt.Fprintf(c.Writer, "<p>You searched for %s</p>", c.Query("q"))
}

func GinRaw(c *gin.Context) {
	name := c.Param("name")
~>	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<h1>"+name+"</h1>"))
}

func EchoHello(c echo.Context) error {
	name := c.QueryParam("name")
~>	return c.HTML(http.StatusOK, "<p>Hello "+name+"</p>")
}

func EchoFormat(c echo.Context) error {
~>	return c.HTML(http.StatusOK, fmt.Sprintf("<strong>%s</strong>", c.FormValue("who")))
}
