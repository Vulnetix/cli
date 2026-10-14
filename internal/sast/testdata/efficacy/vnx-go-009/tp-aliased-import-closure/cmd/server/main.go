package main

import (
	"log"
	"net/http"
	ttmpl "text/template"
)

func main() {
	page := ttmpl.Must(ttmpl.New("c").Parse("<div class=comment>{{.}}</div>"))

	http.HandleFunc("/comment", func(w http.ResponseWriter, r *http.Request) {
		body := r.PostFormValue("body")
~>		page.Execute(w, body)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
