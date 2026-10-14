package render

import (
	"io"
	"text/template"

	"github.com/labstack/echo/v4"
)

// Renderer satisfies echo.Renderer; every c.Render(...) response in the app
// goes through it.
type Renderer struct {
	templates *template.Template
}

func (t *Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
~>	return t.templates.ExecuteTemplate(w, name, data)
}

func Comment(c echo.Context) error {
	t := template.Must(template.New("x").Parse("<p>{{.}}</p>"))
~>	return t.Execute(c.Response().Writer, c.QueryParam("text"))
}
