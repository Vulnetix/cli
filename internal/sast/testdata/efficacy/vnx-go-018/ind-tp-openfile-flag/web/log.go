package web

import (
	"net/http"
	"os"
)

func Append(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("file")
~>	f, err := os.OpenFile("/var/app/"+target, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		http.Error(w, "nope", 500)
		return
	}
	defer f.Close()
	f.WriteString(r.FormValue("line") + "\n")
}
