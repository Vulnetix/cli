package web

import (
	"fmt"
	"net/http"
	"os/exec"
)

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := fmt.Sprintf("ping -c 1 %s", host)
~>	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}
