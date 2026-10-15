package mw

import (
	"log"
	"net/http"
)

func Access(r *http.Request) {
	log.Printf("method=%s url=%s ua=%s", r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	log.Printf("form keys=%d", len(r.Form))
}
