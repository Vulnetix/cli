package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

func GinBack(c *gin.Context) {
~>	c.Redirect(http.StatusFound, c.Query("redirect"))
}

func GinNext(c *gin.Context) {
	target := c.DefaultQuery("next", "/")
~>	c.Redirect(http.StatusFound, target)
}

func EchoOut(c echo.Context) error {
~>	return c.Redirect(http.StatusTemporaryRedirect, c.QueryParam("url"))
}

func FiberTo(c *fiber.Ctx) error {
	to := c.Query("to")
~>	return c.Redirect(to)
}

// A redirect written by hand.
func Manual(w http.ResponseWriter, r *http.Request) {
	loc := r.URL.Query().Get("location")
~>	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}
