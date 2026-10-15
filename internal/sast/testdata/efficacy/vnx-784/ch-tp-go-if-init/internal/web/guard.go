package web

import "net/http"

func RequireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
~>		if c, err := r.Cookie("authenticated"); err == nil && c.Value == "true" {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}
