package api

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

// A column or direction from the request cannot be a bind parameter; it needs
// an allowlist.
func List(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		order := r.URL.Query().Get("order")
~>		q := "SELECT id, name FROM items ORDER BY " + order
		rows, err := db.Query(q)
		if err == nil {
			rows.Close()
		}
	}
}

func Dump(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
~>		rows, err := db.Query("SELECT * FROM " + c.Param("table"))
		if err == nil {
			rows.Close()
		}
	}
}
