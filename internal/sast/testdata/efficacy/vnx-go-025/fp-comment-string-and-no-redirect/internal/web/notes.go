package web

import (
	"log"
	"net/http"
)

// Never do this: http.Redirect(w, r, r.FormValue("next"), http.StatusFound)
func remember(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	log.Printf("http.Redirect(w, r, %q) would be an open redirect", next)
	setPending(r, next)
	w.WriteHeader(http.StatusNoContent)
}

/*
	http.Redirect(w, r, r.URL.Query().Get("u"), http.StatusFound)
*/

func setPending(*http.Request, string) {}
