import os

import psycopg2

DB_HOST = os.environ.get("DB_HOST", "localhost")
BIND = "0.0.0.0"
LOCAL = "http://127.0.0.1:8000/health"
METADATA_URL = "http://169.254.169.254/latest/meta-data/"
ALLOWED_NETS = ["10.0.0.0/8", "172.16.0.0/12"]
DOCS_EXAMPLE_HOST = "203.0.113.10"
__version__ = "1.2.3.4"
OID = "@@sample:1[.]3[.][6][.]1[.]4[.][1][.]3[1]1[.][1]0[.][3][.]4@@"
API_URL = "https://api.example.com/v1"


def connect():
    return psycopg2.connect(host=DB_HOST, dbname="orders")
