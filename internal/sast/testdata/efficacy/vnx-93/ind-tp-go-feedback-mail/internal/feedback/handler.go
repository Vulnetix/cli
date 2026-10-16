package feedback

import (
	"net/http"
	"net/smtp"
)

const supportAddr = "support@example.org"

func Submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	subject := r.PostFormValue("subject")
	body := r.PostFormValue("body")

	msg := []byte("To: " + supportAddr + "\r\n" +
~>		"Subject: " + subject + "\r\n" +
		"\r\n" + body)

	if err := smtp.SendMail("localhost:25", nil, "noreply@example.org", []string{supportAddr}, msg); err != nil {
		http.Error(w, "mail failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
