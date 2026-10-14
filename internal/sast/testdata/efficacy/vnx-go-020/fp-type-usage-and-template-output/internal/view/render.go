package view

import (
	"bytes"
	"html/template"
)

type Page struct {
	Title string
	Body  template.HTML
	Parts []template.HTML
	Attrs map[string]template.HTMLAttr
}

var partial = template.Must(template.New("card").Parse(`<div class="card">{{.}}</div>`))

// The output of executing an html/template is already escaped; wrapping it
// so a parent template does not escape it twice is correct.
func Card(v string) (template.HTML, error) {
	var buf bytes.Buffer
	if err := partial.Execute(&buf, v); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil
}

func Join(parts []template.HTML) template.HTML {
	var out template.HTML
	for _, p := range parts {
		out += p
	}
	return out
}

func Unwrap(v any) string {
	if h, ok := v.(template.HTML); ok {
		return string(h)
	}
	return ""
}
