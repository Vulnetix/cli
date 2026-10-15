package main

import (
	"html/template"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type renderer struct{ t *template.Template }

func (r *renderer) Render(w io.Writer, name string, data any, c echo.Context) error {
~>	return r.t.ExecuteTemplate(w, name, data)
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Renderer = &renderer{t: template.Must(template.ParseGlob("views/*.html"))}
	e.Static("/assets", "public")
	e.GET("/", func(c echo.Context) error {
		return c.Render(http.StatusOK, "home.html", nil)
	})
	e.Logger.Fatal(e.Start(":8080"))
}
