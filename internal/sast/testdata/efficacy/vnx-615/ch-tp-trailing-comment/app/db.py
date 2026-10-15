import os

import psycopg2


def connect():
~>    return psycopg2.connect(host="db", user="app", password=os.environ["DB_PASSWORD"])  # old password: Pr0d#Db2023
