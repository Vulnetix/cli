package oauth

import (
	"net/http"
	"slices"
)

func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	client := s.lookup(r.URL.Query().Get("client_id"))
	redirectURI := r.URL.Query().Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirectURI+"?code="+s.issueCode(r), http.StatusFound)
}

func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	ru := r.FormValue("redirect_uri")
	if ru != s.registered(r) {
		http.Error(w, "mismatch", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, ru, http.StatusFound)
}
