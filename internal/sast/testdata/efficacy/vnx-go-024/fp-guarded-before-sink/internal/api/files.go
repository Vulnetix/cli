package api

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

var hostRE = regexp.MustCompile(`^[a-z0-9.-]+$`)

var allowedModes = map[string]bool{"fast": true, "full": true}

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !hostRE.MatchString(host) {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}
	exec.Command("ping", "-c", "1", host).Run()
}

func Scan(w http.ResponseWriter, r *http.Request) {
	mode := r.FormValue("mode")
	if !allowedModes[mode] {
		http.Error(w, "bad mode", http.StatusBadRequest)
		return
	}
	exec.Command("scanner", "--mode", mode).Run()
}

func Get(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.FormValue("name"))
	os.Open(filepath.Join("/srv/files", name))
	q := url.QueryEscape(r.URL.Query().Get("q"))
	http.Redirect(w, r, "/search?q="+q, http.StatusFound)
}
