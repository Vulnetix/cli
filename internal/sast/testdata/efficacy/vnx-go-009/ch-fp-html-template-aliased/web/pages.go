package web

import (
	htmpl "html/template"
	"net/http"
)

var pages = htmpl.Must(htmpl.ParseFiles("templates/index.html", "templates/item.html"))

func Index(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if err := pages.ExecuteTemplate(w, "index.html", q); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func Item(w http.ResponseWriter, r *http.Request) {
	t := htmpl.Must(htmpl.New("x").Parse("<b>{{.}}</b>"))
	t.Execute(w, r.FormValue("id"))
}
