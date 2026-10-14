package oauth

import (
	"fmt"
	"net/http"
)

func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	code := s.issueCode(r)
~>	http.Redirect(w, r, redirectURI+"?code="+code+"&state="+state, http.StatusFound)
}

func (s *Server) Implicit(w http.ResponseWriter, r *http.Request) {
	tok := s.issueToken(r)
~>	http.Redirect(w, r, r.FormValue("redirect_uri")+"#access_token="+tok, http.StatusFound)
}

func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	back := r.URL.Query().Get("post_logout_redirect_uri")
	s.clear(w)
~>	w.Header().Set("Location", fmt.Sprintf("%s?state=%s", back, r.URL.Query().Get("state")))
	w.WriteHeader(http.StatusSeeOther)
}
