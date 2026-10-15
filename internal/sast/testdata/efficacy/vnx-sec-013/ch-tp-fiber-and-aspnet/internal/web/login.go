package web

import "github.com/gofiber/fiber/v2"

func Login(c *fiber.Ctx) error {
	sid := newSession(c)
~>	c.Cookie(&fiber.Cookie{
		Name:   "session_id",
		Value:  sid,
		Secure: true,
	})
	return c.SendStatus(fiber.StatusNoContent)
}
