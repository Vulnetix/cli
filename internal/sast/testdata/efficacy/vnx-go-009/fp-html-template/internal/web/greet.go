package web

import (
	"html/template"
	"net/http"
)

var greetPage = template.Must(template.New("greet").Parse(`<h1>Hello, {{.Name}}</h1>`))

var pages = template.Must(template.ParseGlob("web/templates/*.html"))

// html/template escapes {{.Name}} for the HTML context it lands in.
func Greet(w http.ResponseWriter, r *http.Request) {
	greetPage.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
}

func Index(w http.ResponseWriter, r *http.Request) {
	pages.ExecuteTemplate(w, "index.html", nil)
}
