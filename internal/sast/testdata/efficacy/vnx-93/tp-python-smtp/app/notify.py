import smtplib

from flask import Flask, request

app = Flask(__name__)


@app.route("/invite", methods=["POST"])
def invite():
    to_addr = request.form["to"]
~>    msg = "To: " + to_addr + "\r\nSubject: Invitation\r\n\r\nJoin us!"
~>    note = f"Reply-To: {request.form['reply']}\r\n"
    with smtplib.SMTP("localhost") as s:
        s.sendmail("noreply@example.com", [to_addr], msg + note)
    return "sent"
