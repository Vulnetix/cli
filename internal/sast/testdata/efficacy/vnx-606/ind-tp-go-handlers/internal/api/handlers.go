package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func (s *Server) Generate(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("times")
	times, err := strconv.Atoi(raw)
	if err != nil {
		http.Error(w, "bad times", http.StatusBadRequest)
		return
	}
~>	for i := 0; i < times; i++ {
		fmt.Fprintln(w, s.ids.Next())
	}
}

func (s *Server) Pages(w http.ResponseWriter, r *http.Request) {
	pages, err := strconv.ParseInt(r.FormValue("pages"), 10, 64)
	if err != nil {
		http.Error(w, "bad pages", http.StatusBadRequest)
		return
	}
~>	for p := range pages {
		s.render(w, int(p))
	}
}

func (s *Server) Retry(c *gin.Context) {
	n, err := strconv.Atoi(c.Query("retries"))
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	attempt := 0
~>	for attempt < n {
		if s.upstream.Ping() == nil {
			c.Status(http.StatusOK)
			return
		}
		attempt++
	}
	c.Status(http.StatusServiceUnavailable)
}
