package web

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

func Document(c *fiber.Ctx) error {
	file, err := c.FormFile("document")
	if err != nil {
		return err
	}
~>	return c.SaveFile(file, fmt.Sprintf("./uploads/%s", file.Filename))
}
