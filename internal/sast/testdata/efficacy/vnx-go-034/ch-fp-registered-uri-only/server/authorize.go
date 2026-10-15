package server

import (
	"net/http"
	"net/url"
)

// The redirect_uri parameter is ignored; the code is always delivered to
// the URI registered for the client.
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	cl, err := s.clients.Get(r.Context(), clientID)
	if err != nil {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	dest := cl.RedirectURI + "?code=" + url.QueryEscape(s.issue(r, cl))
	http.Redirect(w, r, dest, http.StatusFound)
	s.log.Printf("redirect_uri=%q ignored", r.URL.Query().Get("redirect_uri"))
}
