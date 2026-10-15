package notify

import (
	"fmt"
	"net/http"
	"net/smtp"
)

func Contact(w http.ResponseWriter, r *http.Request) {
	from := r.FormValue("from")
	subject := r.FormValue("subject")
~>	msg := []byte("From: " + from + "\r\n" +
		"To: support@example.com\r\n")
~>	hdr := fmt.Sprintf("Subject: %s\r\n\r\n", subject)
	_ = smtp.SendMail("localhost:25", nil, from, []string{"support@example.com"}, append(msg, hdr...))
}
