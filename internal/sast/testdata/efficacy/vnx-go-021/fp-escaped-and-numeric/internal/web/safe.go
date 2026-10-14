package web

import (
	"fmt"
	"html"
	"html/template"
	"net/http"
	"strconv"
)

func Hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<p>Hello, %s!</p>", html.EscapeString(name))
	fmt.Fprintf(w, "<p>%s</p>", template.HTMLEscapeString(r.FormValue("note")))
	safe := html.EscapeString(r.FormValue("title"))
	fmt.Fprintf(w, "<h1>%s</h1>", safe)
	fmt.Fprint(w, "<b>"+html.EscapeString(name)+"</b>")
}

func Count(w http.ResponseWriter, r *http.Request, n int, total float64) {
	fmt.Fprintf(w, "<p>%d items, %.2f total</p>", n, total)
	fmt.Fprintf(w, "<p>%s pages</p>", strconv.Itoa(n))
	fmt.Fprintf(w, "<p>%v found</p>", len(r.Form))
}
