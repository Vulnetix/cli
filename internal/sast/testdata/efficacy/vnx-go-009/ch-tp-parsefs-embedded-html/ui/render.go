package ui

import (
	"embed"
	"text/template"
)

//go:embed templates/*.html
var templateFS embed.FS

~>var views = template.Must(template.ParseFS(templateFS, "templates/*.html"))

func Views() *template.Template {
	return views
}
