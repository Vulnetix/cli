package notify

import (
	"net/http"
	"net/mail"
	"net/smtp"
	"strings"
)

var crlf = strings.NewReplacer("\r", "", "\n", "")

func Contact(w http.ResponseWriter, r *http.Request) {
	addr, err := mail.ParseAddress(r.FormValue("email"))
	if err != nil {
		http.Error(w, "invalid address", http.StatusBadRequest)
		return
	}
	subject := crlf.Replace(r.FormValue("subject"))

	msg := []byte("From: noreply@example.org\r\n" +
		"Reply-To: " + addr.Address + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" + r.FormValue("message"))
	_ = smtp.SendMail("localhost:25", nil, "noreply@example.org", []string{"team@example.org"}, msg)
	w.WriteHeader(http.StatusNoContent)
}
