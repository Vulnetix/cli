package web

import (
	"net/http"
	"runtime"
)

func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				buf := make([]byte, 8192)
				n := runtime.Stack(buf, false)
				w.WriteHeader(http.StatusInternalServerError)
~>				w.Write(buf[:n])
			}
		}()
		next.ServeHTTP(w, r)
	})
}
