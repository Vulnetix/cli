EMAIL_BACKEND = "anymail.backends.mailgun.EmailBackend"
ANYMAIL = {
~>    "MAILGUN_API_KEY": "@@sample:[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8}@@",
    "MAILGUN_SENDER_DOMAIN": "mg.acme.example",
}
