package web

import "net/http"

func Item(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	http.Redirect(w, r, "https://app.example.com/items/"+id, http.StatusFound)
}
