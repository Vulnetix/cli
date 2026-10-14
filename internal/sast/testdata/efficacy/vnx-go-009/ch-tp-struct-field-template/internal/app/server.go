package app

import (
	"net/http"
	"text/template"
)

type Server struct {
	mux  *http.ServeMux
	tmpl *template.Template
}

func New() *Server {
	s := &Server{mux: http.NewServeMux()}
~>	s.tmpl = template.Must(template.ParseGlob("web/templates/*.html"))
	s.mux.HandleFunc("/", s.home)
	return s
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	data := struct{ Search string }{Search: r.URL.Query().Get("s")}
~>	if err := s.tmpl.ExecuteTemplate(w, "home.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
