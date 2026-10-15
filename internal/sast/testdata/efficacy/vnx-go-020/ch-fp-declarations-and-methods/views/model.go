package views

import (
	"bytes"
	"html/template"
)

type Page struct {
	Title string
	Body  template.HTML
}

var empty template.HTML

func (p Page) Rendered(t *template.Template) (template.HTML, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, p); err != nil {
		return empty, err
	}
	return template.HTML(buf.String()), nil
}

// template.HTML(userInput) disables escaping; never call it on request data.
const warning = "do not use template.HTML(r.FormValue(x))"
