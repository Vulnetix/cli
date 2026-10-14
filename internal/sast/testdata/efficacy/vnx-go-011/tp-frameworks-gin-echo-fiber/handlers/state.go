package handlers

import (
	"bytes"
	"encoding/gob"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

type State struct{ Items []string }

func GinRestore(c *gin.Context) {
	var st State
~>	gob.NewDecoder(c.Request.Body).Decode(&st)
}

func EchoRestore(c echo.Context) error {
	var st State
~>	return gob.NewDecoder(c.Request().Body).Decode(&st)
}

func FiberRestore(c *fiber.Ctx) error {
	var st State
~>	return gob.NewDecoder(bytes.NewReader(c.Body())).Decode(&st)
}
