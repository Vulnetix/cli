package notify

import (
	"net/http"
	"net/smtp"
)

// SendInvite mails an invitation to the address the inviter typed.
func SendInvite(w http.ResponseWriter, r *http.Request) {
	to := r.FormValue("to")
	body := "You have been invited to the workspace."
~>	msg := "To: " + to + "\r\nSubject: Workspace invitation\r\n\r\n" + body
	auth := smtp.PlainAuth("", "bot@example.com", "pw", "smtp.example.com")
	if err := smtp.SendMail("smtp.example.com:587", auth, "bot@example.com", []string{"ops@example.com"}, []byte(msg)); err != nil {
		http.Error(w, "send failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
