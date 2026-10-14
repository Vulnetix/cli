package view

import (
	"fmt"
	"html/template"
)

type Link struct {
	Href, Title string
}

// Markup assembled from values and marked safe in one expression.
func (l Link) HTML() template.HTML {
~>	return template.HTML("<a href=\"" + l.Href + "\">" + l.Title + "</a>")
}

func Badge(label string) template.HTML {
~>	return template.HTML(fmt.Sprintf(`<span class="badge">%s</span>`, label))
}

func Row(name string) template.HTML {
	cell := "<td>" + name + "</td>"
~>	return template.HTML(cell)
}
