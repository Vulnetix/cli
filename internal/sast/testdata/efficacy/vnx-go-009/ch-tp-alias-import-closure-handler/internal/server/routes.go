package server

import (
	"net/http"

	tt "text/template"
)

func greet() http.HandlerFunc {
	t := tt.Must(tt.New("greet").Parse("<p>Welcome back, {{.}}!</p>"))
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
~>		_ = t.Execute(w, user)
	}
}
