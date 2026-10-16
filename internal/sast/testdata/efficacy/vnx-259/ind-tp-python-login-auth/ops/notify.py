import smtplib
from email.message import EmailMessage

import pymysql
import requests
from requests.auth import HTTPBasicAuth

GRAFANA = "https://grafana.internal.example.org"


def send_nightly(report):
    msg = EmailMessage()
    msg["Subject"] = "Nightly report"
    msg.set_content(report)
    with smtplib.SMTP("smtp.example.org", 587) as server:
        server.starttls()
~>        server.login("alerts@example.org", "N1ghtly-Rep0rt!")
        server.send_message(msg)


def dashboards(user):
~>    return requests.get(f"{GRAFANA}/api/search", auth=HTTPBasicAuth(user, "Gr4fana-Adm1n"), timeout=10)


def reporting_db():
~>    return pymysql.connect("db.internal", "reporting", "R3p0rting#2023")
