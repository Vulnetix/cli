import os

import requests
from requests.auth import HTTPBasicAuth

DATABASE_URL = "postgres://postgres:Xk9mQ2vpL7wR4z@db/app"
BROKER_URL = f"amqp://guest:{os.environ['MQ_PW']}@mq//"


def status(url):
    return requests.get(url, auth=HTTPBasicAuth("admin", os.environ["ADMIN_PW"]))


def connect(conn):
    return conn.connect(user="root", password=os.environ["DB_PW"])
