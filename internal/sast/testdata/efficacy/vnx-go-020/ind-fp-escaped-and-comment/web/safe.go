package web

import (
	"html"
	"html/template"
	"net/http"
)

func Safe(w http.ResponseWriter, r *http.Request) {
	// template.HTML(r.FormValue("x")) would be an XSS hole, so we do not do it
	escaped := html.EscapeString(r.FormValue("x"))
	t := template.Must(template.New("t").Parse(`<p>{{.}}</p>`))
	t.Execute(w, escaped)
}
