package web

import (
	"net/http"
	"os/exec"
	"regexp"
)

var hostRE = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !hostRE.MatchString(host) {
		http.Error(w, "bad host", 400)
		return
	}
	exec.Command("ping", "-c", "1", host).Run()
}
