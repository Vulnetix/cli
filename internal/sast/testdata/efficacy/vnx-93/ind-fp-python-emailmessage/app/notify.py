import smtplib
from email.message import EmailMessage

from flask import request


def send_feedback():
    msg = EmailMessage()
    msg["From"] = "feedback@example.org"
    msg["To"] = "product@example.org"
    msg["Subject"] = request.form["subject"]
    msg["Reply-To"] = request.form.get("email", "")
    msg.set_content(request.form.get("body", ""))

    with smtplib.SMTP("localhost") as smtp:
        smtp.send_message(msg)
    return "", 204
