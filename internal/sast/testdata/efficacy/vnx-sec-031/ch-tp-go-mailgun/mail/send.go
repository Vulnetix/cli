package mail

import "github.com/mailgun/mailgun-go/v4"

func client() *mailgun.MailgunImpl {
~>	return mailgun.NewMailgun("mg.acme.example", "key-@@sample:[a-f0-9]{32}@@")
}
