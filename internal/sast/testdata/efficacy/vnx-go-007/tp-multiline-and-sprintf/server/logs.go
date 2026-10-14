package server

import (
	"fmt"
	"net/http"
	"os"
)

func Logs(w http.ResponseWriter, r *http.Request) {
	service := r.FormValue("service")
	logPath := fmt.Sprintf("/var/log/%s/current.log", service)
~>	f, err := os.OpenFile(
		logPath,
		os.O_RDONLY,
		0,
	)
	if err != nil {
		return
	}
	defer f.Close()
}

func Theme(w http.ResponseWriter, r *http.Request) {
~>	css, err := os.ReadFile(fmt.Sprintf("themes/%s.css", r.URL.Query().Get("theme")))
	if err == nil {
		w.Write(css)
	}
}
