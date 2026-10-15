package handlers

import (
	"database/sql"
	"net/http"
)

type API struct{ DB *sql.DB }

func (a *API) ByCustomer(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("customer")
~>	rows, err := a.DB.Query("SELECT id, total FROM orders WHERE customer = '" +
		name + "' ORDER BY id")
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}

func (a *API) List(w http.ResponseWriter, r *http.Request) {
	q := "SELECT id, total FROM orders WHERE 1=1"
	if s := r.URL.Query().Get("status"); s != "" {
		q += " AND status = '" + s + "'"
	}
	if c := r.URL.Query().Get("currency"); c != "" {
		q += " AND currency = '" + c + "'"
	}
~>	rows, err := a.DB.Query(q)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
