import smtplib
from email.mime.text import MIMEText

from flask import Flask, request

app = Flask(__name__)


@app.post("/feedback")
def feedback():
    msg = MIMEText(request.form.get("text", ""))
    msg["To"] = "team@example.com"
    msg["From"] = "noreply@example.com"
    reply = request.form.get("email", "")
~>    msg["Reply-To"] = reply
~>    msg['Subject'] = f"Feedback from {request.form['name']}"
    with smtplib.SMTP("localhost") as s:
        s.send_message(msg)
    return "ok"
