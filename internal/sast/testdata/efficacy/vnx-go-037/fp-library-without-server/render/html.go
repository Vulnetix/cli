package render

import (
	"html/template"
	"net/http"
)

type HTML struct {
	Template *template.Template
	Data     any
}

func (r HTML) Render(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return r.Template.Execute(w, r.Data)
}
