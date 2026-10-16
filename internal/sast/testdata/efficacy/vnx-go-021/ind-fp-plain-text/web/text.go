package web

import (
	"fmt"
	"net/http"
)

func Ping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "pong %s\n", r.URL.Query().Get("who"))
}
