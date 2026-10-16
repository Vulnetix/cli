package middleware

import (
	"net/http"
	"strings"
)

func CheckReferer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
~>			if !strings.Contains(r.Header.Get("Referer"), "example.com") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
