package notify

import (
	"net/http"
	"net/smtp"

	"golang.org/x/crypto/ssh"
)

const relay = "smtp.example.org"

func Send(to []string, body []byte) error {
~>	auth := smtp.PlainAuth("", "alerts@example.org", "Sm7p-Relay-1", relay)
	return smtp.SendMail(relay+":587", auth, "alerts@example.org", to, body)
}

func Status(req *http.Request) {
~>	req.SetBasicAuth("monitor", "M0nitor-Api-K")
}

func Bastion() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: "ops",
~>		Auth: []ssh.AuthMethod{ssh.Password("Ssh-Bastion-9")},
	}
}
