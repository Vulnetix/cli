package main

import "net/http"

func main() {
	http.Handle("/", secureHeaders(http.HandlerFunc(page)))
	http.ListenAndServe(":8080", nil)
}

func page(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "index.html", nil)
}
