import os
import smtplib

import pymysql
from requests.auth import HTTPBasicAuth

from app.config import settings


def send(msg):
    with smtplib.SMTP(settings.SMTP_HOST, 587) as server:
        server.starttls()
        server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        server.send_message(msg)


def db():
    return pymysql.connect(settings.DB_HOST, settings.DB_USER, settings.DB_PASSWORD)


def grafana_auth(user, password):
    return HTTPBasicAuth(user, password)
