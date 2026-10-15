package mail

import "github.com/sendgrid/sendgrid-go"

const (
	fromAddress = "noreply@example.org"
~>	sendgridAPIKey = "@@sample:SG\.[A-Za-z0-9]{22}\.[A-Za-z0-9]{43}@@"
)

func client() *sendgrid.Client {
	return sendgrid.NewSendClient(sendgridAPIKey)
}
