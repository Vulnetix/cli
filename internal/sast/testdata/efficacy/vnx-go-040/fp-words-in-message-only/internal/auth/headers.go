package auth

import (
	"log"
	"net/http"
)

func trace(r *http.Request) {
	log.Printf("request id %s token-scoped route", r.Header.Get("X-Request-Id"))
}
