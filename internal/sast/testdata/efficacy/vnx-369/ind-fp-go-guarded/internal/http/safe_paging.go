package http

import (
	"fmt"
	"net/http"
	"strconv"
)

// see https://example.com/docs/paging/limits for the defaults
func safePagesHandler(w http.ResponseWriter, r *http.Request) {
	total := 1000
	perPage, err := strconv.Atoi(r.URL.Query().Get("per_page"))
	if err != nil || perPage <= 0 {
		http.Error(w, "bad per_page", http.StatusBadRequest)
		return
	}
	pages := total / perPage
	fmt.Fprintf(w, "%d pages / %s", pages, "api/v1/pages")
}
