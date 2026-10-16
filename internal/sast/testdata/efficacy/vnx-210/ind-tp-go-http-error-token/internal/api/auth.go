package api

import (
	"net/http"
	"strings"
)

func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, err := s.verifier.Verify(tokenString); err != nil {
~>			http.Error(w, "token rejected: "+tokenString, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
