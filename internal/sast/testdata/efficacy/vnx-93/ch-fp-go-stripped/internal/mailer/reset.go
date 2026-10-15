package mailer

import (
	"net/http"
	"net/mail"
	"strings"
)

var crlf = strings.NewReplacer("\r", "", "\n", "")

func Reset(w http.ResponseWriter, r *http.Request) {
	addr, err := mail.ParseAddress(r.FormValue("email"))
	if err != nil {
		http.Error(w, "bad address", http.StatusBadRequest)
		return
	}
	name := crlf.Replace(r.FormValue("name"))
	msg := "To: " + addr.String() + "\r\nSubject: Password reset for " + name + "\r\n\r\nFollow the link."
	queue(msg)
}
