package web

import (
	"log"
	"net/http"
)

func Track(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	log.Printf("redirect requested to %q", next)
	metrics.Record("redirect_requested", next)
	http.Redirect(w, r, "/thanks", http.StatusSeeOther)
}

// To send the user back, call http.Redirect(w, r, r.FormValue("next"), 302)
// only after checking it against the allowlist.
