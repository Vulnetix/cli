package api

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// A bind parameter is the safe way to pass a request value to SQL, and a
// number parsed with strconv cannot carry a payload.
func User(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name")
		rows, err := db.Query("SELECT id FROM users WHERE name = $1", name)
		if err == nil {
			rows.Close()
		}
		row := db.QueryRowContext(r.Context(), "SELECT id FROM users WHERE email = ?", r.FormValue("email"))
		_ = row
		id, err := strconv.Atoi(r.URL.Query().Get("id"))
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		db.Exec("DELETE FROM sessions WHERE user_id = " + strconv.Itoa(id))
	}
}

func GinUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant := c.Param("tenant")
		db.QueryContext(c, "SELECT * FROM t WHERE tenant = $1", tenant)
	}
}
