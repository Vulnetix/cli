package web

import (
	"fmt"
	"net/http"
)

func Hello(w http.ResponseWriter, r *http.Request) {
~>	fmt.Fprintf(w, "<html><body>Hello %s</body></html>", name(r))
}
