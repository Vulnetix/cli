package main

import (
	"log"
	"net/http"
	"text/template"
)

var layout *template.Template

func init() {
	var err error
~>	layout, err = template.ParseFiles(
		"views/layout.gohtml",
		"views/search.gohtml",
	)
	if err != nil {
		log.Fatal(err)
	}
}

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
~>	err := layout.ExecuteTemplate(w, "layout", map[string]string{"Query": q})
	if err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/search", search)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
