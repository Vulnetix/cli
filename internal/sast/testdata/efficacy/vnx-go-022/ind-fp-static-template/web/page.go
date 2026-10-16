package web

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("home").Parse(`<h1>{{.Title}}</h1>`))

func Home(w http.ResponseWriter, r *http.Request) {
	// template.New("x").Parse(r.FormValue("t")) would be SSTI; we only execute a fixed one
	page.Execute(w, map[string]string{"Title": r.FormValue("title")})
}
