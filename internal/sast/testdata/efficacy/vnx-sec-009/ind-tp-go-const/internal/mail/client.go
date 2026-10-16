package mail

import (
	"bytes"
	"net/http"
)

~>const sendgridKey = "@@sample:SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}@@"

func Send(body []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sendgridKey)
	return http.DefaultClient.Do(req)
}
