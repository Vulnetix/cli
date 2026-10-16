package api

import (
	"net/http"
	"strconv"
)

~>// TODO: add authentication before exposing this handler
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
~>	id := r.URL.Query().Get("id") // FIXME: id is not validated
	n, _ := strconv.Atoi(id)
	/*
~>	 * XXX: missing CSRF protection on this form post
	 */
	s.export(w, n)
}
