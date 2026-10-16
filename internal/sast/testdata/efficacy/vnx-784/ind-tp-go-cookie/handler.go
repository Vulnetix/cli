package web

import "net/http"

func Admin(w http.ResponseWriter, r *http.Request) {
~>	if c, err := r.Cookie("user_role"); err == nil && c.Value == "admin" {
		serveAdmin(w, r)
		return
	}
	http.Error(w, "forbidden", 403)
}
