package notify

import (
	"net/http"
	"strings"
)

func Contact(w http.ResponseWriter, r *http.Request) {
	from := strings.NewReplacer("\r", "", "\n", "").Replace(r.FormValue("from"))
	msg := []byte("From: " + from + "\r\n")
	body := r.FormValue("body")
	_ = append(msg, []byte("\r\n"+body)...)
	_ = msg
}
