package sms

import "github.com/twilio/twilio-go"

const accountSid = "AC@@sample:[a-f0-9]{32}@@"
~>const authToken = "@@sample:[a-f0-9]{32}@@"

func client() *twilio.RestClient {
	return twilio.NewRestClientWithParams(twilio.ClientParams{Username: accountSid, Password: authToken})
}
