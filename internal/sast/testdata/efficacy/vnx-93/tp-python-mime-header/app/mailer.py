from email.mime.text import MIMEText

from flask import request


def send_feedback():
    msg = MIMEText(request.form["body"])
~>    msg["Subject"] = request.form["subject"]
    sender = request.form.get("email")
~>    msg['Reply-To'] = sender
    msg["To"] = "feedback@example.com"
    return msg
