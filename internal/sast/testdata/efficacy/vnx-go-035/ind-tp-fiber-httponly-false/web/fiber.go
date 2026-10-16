package web

import "github.com/gofiber/fiber/v2"

func handler(c *fiber.Ctx) error {
~>	c.Cookie(&fiber.Cookie{Name: "sid", Value: "abc", HTTPOnly: false, Secure: true})
	return c.SendStatus(204)
}
