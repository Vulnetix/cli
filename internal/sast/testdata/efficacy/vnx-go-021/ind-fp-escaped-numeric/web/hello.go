package web

import (
	"fmt"
	"html"
	"net/http"
)

func Hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<p>Hello, %s!</p>", html.EscapeString(name))
	n := len(name)
	fmt.Fprintf(w, "<p>%d characters</p>", n)
	fmt.Fprint(w, "<footer>static footer</footer>")
}
