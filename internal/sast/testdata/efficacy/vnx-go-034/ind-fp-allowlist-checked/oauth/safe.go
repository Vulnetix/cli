package oauth

import (
	"net/http"
	"slices"
)

func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	client := s.lookup(r.FormValue("client_id"))
	redirectURI := r.FormValue("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirectURI+"?code="+s.issueCode(r), http.StatusFound)
}
