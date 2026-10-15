package web

import "net/http"

func Admin(w http.ResponseWriter, r *http.Request) {
~>	c, err := r.Cookie("role")
	if err != nil || c.Value != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Write([]byte("ok"))
}
