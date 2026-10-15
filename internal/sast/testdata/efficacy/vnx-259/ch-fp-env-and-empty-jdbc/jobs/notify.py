import os
import smtplib


def send(msg, sender):
    with smtplib.SMTP_SSL("smtp.example.com", 465) as server:
        server.login(sender, os.environ["SMTP_PASSWORD"])
        server.login(sender, get_secret("smtp"))
        print('server.login(sender, "Al3rtsMa1l!")')
