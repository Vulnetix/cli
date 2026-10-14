package web

import (
	"fmt"
	"net/http"
	"net/url"
)

func search(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/search?q="+url.QueryEscape(r.FormValue("q")), http.StatusFound)
}

func toLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, "https://accounts.example.com/login?next="+url.QueryEscape(next), http.StatusFound)
}

func docs(w http.ResponseWriter, r *http.Request) {
	page := r.FormValue("page")
	http.Redirect(w, r, "https://docs.example.com/"+page, http.StatusFound)
}

func profile(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	dest := fmt.Sprintf("/users/%s/profile", user)
	http.Redirect(w, r, dest, http.StatusFound)
}
