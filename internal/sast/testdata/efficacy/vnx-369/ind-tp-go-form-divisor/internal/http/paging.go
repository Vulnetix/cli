package http

import (
	"fmt"
	"net/http"
	"strconv"
)

func pagesHandler(w http.ResponseWriter, r *http.Request) {
	total := 1000
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
~>	pages := total / perPage
	fmt.Fprintf(w, "%d pages", pages)
}
