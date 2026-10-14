package web

import (
	"log"
	"net/http"
	"text/template"
)

var greetPage = template.Must(template.New("greet").Parse(`<!doctype html>
<html><body><h1>Hello, {{.Name}}</h1></body></html>`))

// Greet echoes the visitor's name back inside an HTML page. text/template
// writes {{.Name}} verbatim, so ?name=<script>... runs in the browser.
func Greet(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{"Name": r.URL.Query().Get("name")}
~>	if err := greetPage.Execute(w, data); err != nil {
		log.Printf("greet: %v", err)
	}
}

func Profile(rw http.ResponseWriter, req *http.Request) {
	tmpl, err := template.ParseFiles("templates/profile.tmpl")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
~>	_ = tmpl.Execute(
		rw,
		map[string]string{"Bio": req.FormValue("bio")},
	)
}
