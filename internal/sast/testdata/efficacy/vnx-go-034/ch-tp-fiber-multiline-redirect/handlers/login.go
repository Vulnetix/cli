package handlers

import (
	"github.com/gofiber/fiber/v2"
)

func (a *App) Callback(c *fiber.Ctx) error {
	callbackURL := c.Query("callback_url")
	code, err := a.store.NewCode(c.Context())
	if err != nil {
		return fiber.ErrInternalServerError
	}
~>	return c.Redirect(
		callbackURL+"?code="+code,
		fiber.StatusFound,
	)
}
