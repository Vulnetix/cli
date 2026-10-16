package notify

import (
	"net/http"
	"net/smtp"
	"os"
)

func Auth() smtp.Auth {
	return smtp.PlainAuth("", os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASSWORD"), os.Getenv("SMTP_HOST"))
}

func Sign(req *http.Request, user, pass string) {
	req.SetBasicAuth(user, pass)
}
