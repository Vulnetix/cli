import requests

auth_token = "@@sample:[a-f0-9]{32}@@"
requests.post("https://api.mailgun.net/v3/messages", auth=("api", auth_token))
