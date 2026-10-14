package files

import "github.com/gofiber/fiber/v2"

func Asset(c *fiber.Ctx) error {
~>	return c.SendFile("./public/" + c.Params("name"))
}
