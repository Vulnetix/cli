package web

import (
	"net/http"
	"os/exec"
)

var allowedTargets = map[string]string{"home": "/", "docs": "/docs"}

func Go(w http.ResponseWriter, r *http.Request) {
	dest, ok := allowedTargets[r.FormValue("t")]
	if !ok {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
	if r.FormValue("refresh") != "" {
		exec.Command("systemctl", "reload", "app").Run()
	}
}
