package api

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Server struct {
	db   *sql.DB
	gorm *gorm.DB
}

// The sort column comes from the query string; a placeholder cannot carry an
// identifier, so it reaches the SQL text as written.
func (s *Server) Items(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	query := "SELECT id, name FROM items ORDER BY " + sort
~>	rows, err := s.db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}

func (s *Server) Dump(c *gin.Context) {
	table := c.Param("table")
	var out []map[string]any
~>	s.gorm.Raw(fmt.Sprintf("SELECT * FROM %s", table)).Scan(&out)
	c.JSON(http.StatusOK, out)
}
