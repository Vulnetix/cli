package docs

import (
	"fmt"
	"net/http"
)

const example = `
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
`

func Help(w http.ResponseWriter, r *http.Request) {
	// Do not write http.Redirect(w, r, r.FormValue("url"), 302) in a handler.
	fmt.Fprintf(w, "never call http.Redirect(w, r, r.FormValue(\"url\"), 302): %s", example)
}
