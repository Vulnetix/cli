from twilio.rest import Client

account_sid = "AC@@sample:[0-9a-f]{32}@@"
~>auth_token = "@@sample:[0-9a-f]{32}@@"
client = Client(account_sid, auth_token)
