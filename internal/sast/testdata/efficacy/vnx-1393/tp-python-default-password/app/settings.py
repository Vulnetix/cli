import os

import psycopg2

~>DB_PASSWORD = "postgres"
~>ADMIN_PASSWORD = 'admin'

DATABASES = {
    "default": {
        "USER": "app",
~>        "PASSWORD": "changeme",
    }
}


def connect():
~>    return psycopg2.connect(host="db", user="app", password="password")


~>SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "secret")
~>REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', 'default')
