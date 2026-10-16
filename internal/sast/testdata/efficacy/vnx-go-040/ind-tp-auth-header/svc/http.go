package svc

import (
	"log"
	"net/http"
)

func dump(r *http.Request) {
~>	log.Printf("request auth header: %s", r.Header.Get("Authorization"))
}
