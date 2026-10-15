package api

import (
	"net/http"
	"os"
)

func Note(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	os.WriteFile("/var/lib/app/last-note.txt", []byte(msg), 0o600)
	f, _ := os.OpenFile("/var/log/app/notes.log", os.O_APPEND|os.O_WRONLY, 0o600)
	defer f.Close()
	f.WriteString(r.URL.Query().Get("extra"))
}
