import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Blueprint, redirect, request

bp = Blueprint("support", __name__)


@bp.route("/support/ticket", methods=["POST"])
def open_ticket():
    customer = request.form.get("customer", "anonymous")
    body = request.form.get("description", "")

    msg = MIMEMultipart()
    msg["From"] = "helpdesk@example.org"
    msg["To"] = "tickets@example.org"
~>    msg["Reply-To"] = request.form["email"]
~>    msg.add_header("X-Customer", customer)
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP("localhost") as smtp:
        smtp.send_message(msg)
    return redirect("/support/thanks")
