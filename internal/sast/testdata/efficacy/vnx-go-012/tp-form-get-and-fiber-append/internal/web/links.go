package web

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func Preload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		return
	}
	asset := r.Form.Get("asset")
~>	w.Header().Add("Link", "<"+asset+">; rel=preload")
}

func FiberLink(c *fiber.Ctx) error {
	next := c.Query("next")
~>	c.Append("Link", next)
	return nil
}
