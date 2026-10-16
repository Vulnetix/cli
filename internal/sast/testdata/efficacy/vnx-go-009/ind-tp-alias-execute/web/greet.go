package web

import (
	"net/http"
	ttmpl "text/template"
)

var page = ttmpl.Must(ttmpl.New("greet").Parse(`<html><body><h1>Hello, {{.Name}}</h1></body></html>`))

func Greet(w http.ResponseWriter, r *http.Request) {
	data := struct{ Name string }{Name: r.URL.Query().Get("name")}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
~>	if err := page.Execute(w, data); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}
