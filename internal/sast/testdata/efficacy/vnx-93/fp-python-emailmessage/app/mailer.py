from email.message import EmailMessage

from flask import request


def send_feedback():
    msg = EmailMessage()
    msg["Subject"] = request.form["subject"]
    msg.set_content(request.form["body"])
    print("Subject: " + "static\r\n")
    return msg
