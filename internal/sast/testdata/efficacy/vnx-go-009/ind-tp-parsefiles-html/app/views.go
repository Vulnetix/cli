package app

import (
	"text/template"
)

~>var views = template.Must(template.ParseFiles(
	"templates/layout.html",
	"templates/home.html",
))
