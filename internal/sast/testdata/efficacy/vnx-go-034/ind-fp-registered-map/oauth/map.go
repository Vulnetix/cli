package oauth

import "net/http"

func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	ru := r.PostFormValue("redirect_uri")
	if _, ok := s.client.RedirectURIs[ru]; !ok {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, ru+"?code=1", http.StatusFound)
}
