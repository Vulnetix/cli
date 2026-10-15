package web

import (
	"html/template"
	"net/http"
)

var tmpl = template.Must(template.New("p").Parse(`<p>{{.}}</p>`))

func Page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, r.FormValue("q"))
	w.Write([]byte("<hr><footer>static footer</footer>"))
}
