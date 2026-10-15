EMAIL_BACKEND = "anymail.backends.mailgun.EmailBackend"
ANYMAIL = {
~>    "MAILGUN_API_KEY": "key-@@sample:[a-f0-9]{32}@@",
    "MAILGUN_SENDER_DOMAIN": "mg.acme.example",
}
