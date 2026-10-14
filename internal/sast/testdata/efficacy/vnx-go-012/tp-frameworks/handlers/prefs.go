package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
	"github.com/valyala/fasthttp"
)

func GinPrefs(c *gin.Context) {
	c.Set("user", "anon")
~>	c.Header("X-Lang", c.Query("lang"))
}

func EchoPrefs(c echo.Context) error {
	ref := c.QueryParam("ref")
~>	c.Response().Header().Set("X-Ref", ref)
	return nil
}

func FiberPrefs(c *fiber.Ctx) error {
~>	c.Set("X-Theme", c.Query("theme"))
	return c.SendStatus(204)
}

func FastPrefs(ctx *fasthttp.RequestCtx) {
	q := string(ctx.QueryArgs().Peek("q"))
~>	ctx.Response.Header.Set("X-Query", q)
}
