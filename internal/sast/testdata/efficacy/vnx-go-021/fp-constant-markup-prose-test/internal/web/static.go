package web

import (
	"fmt"
	"net/http"
)

const productName = "Example"

// Markup with only constant values interpolated.
func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "<h1>Welcome</h1>")
	fmt.Fprintf(w, "<h1>%s</h1>", "Welcome")
	fmt.Fprintf(w, "<title>%s</title>", productName)
	fmt.Fprintf(w, "<p>Status: %s</p>", http.StatusText(http.StatusOK))
	// fmt.Fprintf(w, "<p>%s</p>", r.FormValue("x"))
	help := "fmt.Fprintf(w, \"<p>%s</p>\", name) is XSS"
	_ = help
}
