package oauth

import "net/http"

type client struct {
	RedirectURIs map[string]struct{}
}

func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	cl := s.clients[r.URL.Query().Get("client_id")]
	if _, ok := cl.RedirectURIs[redirectURI]; !ok {
		http.Error(w, "unknown redirect_uri", http.StatusBadRequest)
		return
	}
	code := s.issue(r)
	http.Redirect(w, r, redirectURI+"?code="+code, http.StatusFound)
}
