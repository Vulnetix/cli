package api

import (
	"log/slog"
	"net/http"
)

func trace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
~>		slog.Debug("request", "path", r.URL.Path, "authorization", r.Header.Get("Authorization"))
		next.ServeHTTP(w, r)
	})
}
