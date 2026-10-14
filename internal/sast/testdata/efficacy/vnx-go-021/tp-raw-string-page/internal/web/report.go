package web

import (
	"fmt"
	"net/http"
)

type Report struct {
	Title, Owner string
}

// A page written as one raw string; the verbs sit lines below Fprintf.
func Show(w http.ResponseWriter, r *http.Request, rep Report) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
~>	fmt.Fprintf(w, `<!doctype html>
<html>
<head><title>%s</title></head>
<body><h1>%s</h1><p>Owner: %s</p></body>
</html>`, rep.Title, rep.Title, rep.Owner)
}
