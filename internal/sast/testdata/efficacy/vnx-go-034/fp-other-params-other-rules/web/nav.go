package web

import "net/http"

// Plain open redirects on a "next" parameter belong to VNX-GO-005/VNX-GO-025.
func back(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, "/app/"+next, http.StatusFound)
}

func home(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}
