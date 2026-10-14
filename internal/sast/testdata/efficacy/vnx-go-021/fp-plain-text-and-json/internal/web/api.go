package web

import (
	"fmt"
	"net/http"
)

// No markup in the format: a browser does not parse plain text as HTML.
func Hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "Hello %s", name)
	fmt.Fprintf(w, "limit < %s and > %s", r.FormValue("lo"), r.FormValue("hi"))
	fmt.Fprintf(w, "{\"name\": %q}", name)
}

// The handler declares the body as plain text or JSON before writing.
func Echo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "<p>%s</p>", r.FormValue("msg"))
}

func Status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"html": "<b>%s</b>"}`, r.FormValue("id"))
}
