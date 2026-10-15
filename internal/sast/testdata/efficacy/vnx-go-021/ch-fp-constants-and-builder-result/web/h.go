package web

import (
	"fmt"
	"net/http"
)

const appName = "Inventory"

const footer = "<footer>(c) Example Ltd</footer>"

func Home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<title>%s</title>", appName)
	fmt.Fprint(w, "<body>", footer, "</body>")
	w.Write([]byte("<p>" + appName + "</p>"))
}
