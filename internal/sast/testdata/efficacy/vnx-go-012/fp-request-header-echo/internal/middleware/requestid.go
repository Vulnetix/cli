package middleware

import (
	"net/http"

	"github.com/google/uuid"
)

// RequestID propagates the caller's correlation id. A client can only set its
// own request headers, so echoing one back affects nobody else.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-Id", id)
		w.Header().Set("X-Forwarded-Proto", r.Header.Get("X-Forwarded-Proto"))
		next.ServeHTTP(w, r)
	})
}
