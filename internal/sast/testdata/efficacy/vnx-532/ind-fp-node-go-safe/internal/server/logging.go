package server

import (
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
)

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request", "method", r.Method, "path", r.URL.Path, "ua", r.Header.Get("User-Agent"))
		log.Printf("authenticated=%t", r.Header.Get("Authorization") != "")
		log.Printf("form fields=%d", len(r.PostForm))
		next.ServeHTTP(w, r)
	})
}

func debugDump(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.Header.Del("Authorization")
		clone.Header.Del("Cookie")
		dump, err := httputil.DumpRequest(clone, false)
		if err == nil {
			log.Println(string(dump))
		}
		next.ServeHTTP(w, r)
	})
}
