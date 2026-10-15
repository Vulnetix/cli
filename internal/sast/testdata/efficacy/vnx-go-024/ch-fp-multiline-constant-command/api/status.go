package api

import (
	"log"
	"net/http"
	"os/exec"
)

func Status(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	out, err := exec.Command(
		"git", "-C", "/srv/checkout",
		"status", "--short",
	).Output()
	log.Printf("status for %s: %v", repo, err)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(out)
}
