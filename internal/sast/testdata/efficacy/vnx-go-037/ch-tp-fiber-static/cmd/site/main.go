package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

func main() {
	app := fiber.New(fiber.Config{Views: html.New("./views", ".html")})
~>	app.Static("/", "./public")
	app.Get("/about", func(c *fiber.Ctx) error {
		return c.Render("about", fiber.Map{"Title": "About"})
	})
	log.Fatal(app.Listen(":3000"))
}
