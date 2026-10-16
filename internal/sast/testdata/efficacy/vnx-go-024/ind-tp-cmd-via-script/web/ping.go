package web

import (
	"net/http"
	"os/exec"
)

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	script := "ping -c 1 " + host
~>	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}
