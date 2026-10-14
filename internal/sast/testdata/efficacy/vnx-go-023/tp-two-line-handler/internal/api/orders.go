package api

import (
	"database/sql"
	"net/http"
)

type API struct {
	DB *sql.DB
}

// The id is concatenated after "= " with no quotes and no bind parameter.
func (a *API) Order(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
~>	query := "SELECT id, total FROM orders WHERE id = " + id
	rows, err := a.DB.Query(query)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}

func (a *API) Rename(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	uid := r.FormValue("uid")
~>	stmt := `UPDATE users SET display_name = '` + name + `' WHERE id = ` + uid
	a.DB.Exec(stmt)
}
