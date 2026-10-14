package handlers

import (
	"net/http"
	"text/template"

	"github.com/gin-gonic/gin"
)

type Server struct {
	views *template.Template
}

func NewServer() *Server {
	return &Server{views: template.Must(template.New("views").Parse(`{{define "results"}}<p>No results for {{.Q}}</p>{{end}}`))}
}

func (s *Server) Search(c *gin.Context) {
	q := c.Query("q")
	c.Status(http.StatusOK)
~>	s.views.ExecuteTemplate(c.Writer, "results", gin.H{"Q": q})
}
