package web

import (
	"fmt"
	"net/http"
)

func Hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
~>	fmt.Fprintf(w, "<p>Hello, %s!</p>", name)
}

// A not-found page that reflects the path back into markup.
func NotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
~>	fmt.Fprintf(w, "<h1>404</h1><p>No page at %v</p>", r.URL.Path)
}

// The value comes from storage, not the request: stored XSS is the same bug.
func Comments(w http.ResponseWriter, r *http.Request, list []string) {
	fmt.Fprint(w, "<ul>")
	for _, c := range list {
~>		fmt.Fprintf(w, "<li class=\"comment\">%s</li>\n", c)
	}
	fmt.Fprint(w, "</ul>")
}
