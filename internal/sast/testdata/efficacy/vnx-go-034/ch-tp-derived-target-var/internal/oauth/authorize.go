package oauth

import (
	"net/http"
	"net/url"
)

func (s *Server) Approve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	code, err := s.codes.Issue(r.Context(), q.Get("client_id"))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	target := redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
~>	http.Redirect(w, r, target, http.StatusFound)
}
