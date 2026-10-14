package ui

import (
	"embed"
	"text/template"
)

//go:embed views/*.html
var viewsFS embed.FS

// Pages is executed by the handlers in pages.go. Loading .html files with
// text/template means nothing rendered through them is HTML-escaped.
~>var Pages = template.Must(template.ParseGlob("web/templates/*.html"))

~>var Embedded = template.Must(template.New("").ParseFS(viewsFS, "views/*.html"))

func Layout() (*template.Template, error) {
~>	return template.ParseFiles(
		"web/layout.gohtml",
		"web/nav.gohtml",
	)
}
