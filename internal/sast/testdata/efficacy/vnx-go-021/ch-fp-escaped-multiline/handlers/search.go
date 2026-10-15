package handlers

import (
	"fmt"
	"html"
	"html/template"
	"net/http"
	"strconv"
)

func Search(w http.ResponseWriter, r *http.Request) {
	q := html.EscapeString(r.URL.Query().Get("q"))
	fmt.Fprintf(w, "<h2>Results for %s</h2>", q)
	fmt.Fprintf(w,
		"<p>%s</p>",
		template.HTMLEscapeString(r.FormValue("note")))
	page, _ := strconv.Atoi(r.FormValue("page"))
	fmt.Fprintf(w, "<span>page %d</span>", page)
	fmt.Fprint(w, "<footer>", strconv.Itoa(page), "</footer>")
}
