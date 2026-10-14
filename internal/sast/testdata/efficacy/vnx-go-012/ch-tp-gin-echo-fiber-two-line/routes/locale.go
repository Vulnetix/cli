package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

func GinLocale(c *gin.Context) {
	lang := c.Query("lang")
~>	c.Header("Content-Language", lang)
	c.String(200, "ok")
}

func GinDefault(c *gin.Context) {
	cb := c.DefaultQuery("callback", "cb")
~>	c.Writer.Header().Set("X-Callback", cb)
}

func EchoTrace(c echo.Context) error {
	trace := c.QueryParam("trace")
~>	c.Response().Header().Set("X-Trace-Id", trace)
	return c.NoContent(204)
}

func FiberUser(c *fiber.Ctx) error {
~>	c.Set("X-User", c.Params("user"))
	return c.SendStatus(204)
}
