package auth

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

~>func Login(c echo.Context) error {
	return c.JSON(http.StatusOK, nil)
}

~>func HandleSignIn(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusOK)
}

~>func (h *Handler) Authenticate(w http.ResponseWriter,
	r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
