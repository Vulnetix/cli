package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("Authorization")
~>	if tok != s.adminToken {
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

func (s *Server) checkSession(sessionToken string) bool {
~>	return sessionToken == s.sessionToken
}

func (s *Server) resume(cookie string) bool {
	sum := sha256.Sum256([]byte(cookie))
~>	return hex.EncodeToString(sum[:]) == s.resumeDigest
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request, apiKey string) {
~>	if apiKey != s.cfg.APIKey {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
