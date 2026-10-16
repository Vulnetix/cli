package server

import (
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
)

func debugMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dump, err := httputil.DumpRequest(r, true)
		if err == nil {
~>			log.Println(string(dump))
		}
		next.ServeHTTP(w, r)
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
~>	log.Printf("login form: %v", r.PostForm)
~>	slog.Info("login headers", "headers", r.Header)
~>	log.Printf("authorization=%s", r.Header.Get("Authorization"))
	w.WriteHeader(http.StatusNoContent)
}
