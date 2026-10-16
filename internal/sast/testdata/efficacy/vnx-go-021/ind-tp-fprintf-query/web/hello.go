package web

import (
	"fmt"
	"net/http"
)

func Hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
~>	fmt.Fprintf(w, "<p>Hello, %s!</p>", name)
}
