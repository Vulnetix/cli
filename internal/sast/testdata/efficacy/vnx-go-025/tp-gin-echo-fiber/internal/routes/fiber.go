package routes

import "github.com/gofiber/fiber/v2"

func Out(c *fiber.Ctx) error {
	link := c.Query("link")
~>	return c.Redirect(link, fiber.StatusFound)
}
