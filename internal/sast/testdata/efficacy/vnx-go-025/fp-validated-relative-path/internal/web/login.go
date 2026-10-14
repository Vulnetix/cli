package web

import (
	"net/http"
	"strings"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (s *Server) handlePick(w http.ResponseWriter, r *http.Request) {
	page := r.FormValue("page")
	switch page {
	case "/settings", "/billing":
	default:
		page = "/"
	}
	http.Redirect(w, r, page, http.StatusSeeOther)
}
