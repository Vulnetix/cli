package fast

import (
	"text/template"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

var hello = template.Must(template.New("h").Parse(`<h1>{{.}}</h1>`))

func Fast(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("text/html")
~>	hello.Execute(ctx, string(ctx.QueryArgs().Peek("name")))
}

func Fiber(c *fiber.Ctx) error {
	c.Type("html")
~>	return hello.Execute(c, c.Query("name"))
}
