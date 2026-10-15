import smtplib
from email.message import EmailMessage

SMTP_HOST = "smtp.internal"


def send_digest(recipients, body):
    for rcpt in recipients:
        msg = EmailMessage()
        msg["To"] = rcpt
        msg.set_content(body)
~>        server = smtplib.SMTP(SMTP_HOST, 587)
        server.starttls()
        server.send_message(msg)
        server.quit()
