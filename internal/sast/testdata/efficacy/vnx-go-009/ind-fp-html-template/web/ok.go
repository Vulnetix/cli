package web

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("greet").Parse(`<h1>Hello, {{.Name}}</h1>`))

func Greet(w http.ResponseWriter, r *http.Request) {
	page.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
	_ = template.ParseGlob
}
