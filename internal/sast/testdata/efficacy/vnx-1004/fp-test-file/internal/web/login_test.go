package web

import "net/http"

func fixture() *http.Cookie {
	return &http.Cookie{Name: "session", Value: "abc"}
}
