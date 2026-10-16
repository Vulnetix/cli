package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	body, _ := readBody(r)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(body)
	expected := mac.Sum(nil)
	got, _ := hex.DecodeString(r.Header.Get("X-Hub-Signature-256"))
~>	_ = hmac.Equal(got, expected)
	s.process(body)
	w.WriteHeader(http.StatusNoContent)
}
