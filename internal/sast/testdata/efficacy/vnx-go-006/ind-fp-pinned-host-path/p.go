package web

import (
	"net/http"
	"net/url"
)

func User(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	http.Get("https://api.example.com/users/" + url.PathEscape(id))
}
