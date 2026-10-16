import smtplib
from email.message import EmailMessage
from sqlalchemy import create_engine
from settings import SMTP_HOST, DB_URL


def notify(users):
    for user in users:
~>        engine = create_engine(DB_URL)
~>        server = smtplib.SMTP(SMTP_HOST, 587)
        server.starttls()
        msg = EmailMessage()
        msg["To"] = user.email
        msg.set_content("hello")
        server.send_message(msg)
        server.quit()
