package web

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

func updateProfile(c echo.Context) error {
	p := new(Profile)
~>	if err := c.Bind(p); err != nil {
		return err
	}
	return repo.Update(p)
}

func createOrder(c *fiber.Ctx) error {
	var o Order
~>	if err := c.BodyParser(&o); err != nil {
		return err
	}
	return orders.Insert(c.Context(), &o)
}

func importUser(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var u User
~>	_ = json.Unmarshal(body, &u)
	_, _ = coll.InsertOne(r.Context(), u)
}
