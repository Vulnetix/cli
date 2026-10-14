package api

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// The sort column comes straight from the query string. An identifier cannot
// be a bind parameter, so this needs an allowlist, not a placeholder.
func ListItems(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sort := r.URL.Query().Get("sort")
~>		query := fmt.Sprintf("SELECT id, title FROM items ORDER BY %s", sort)
		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rows.Close()
	}
}

func Table(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
~>		rows, err := db.Query(fmt.Sprintf("SELECT * FROM %s LIMIT 50", c.Query("table")))
		if err == nil {
			rows.Close()
		}
	}
}
