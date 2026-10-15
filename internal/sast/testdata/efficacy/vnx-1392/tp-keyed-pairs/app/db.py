import mysql.connector


def connect():
~>    return mysql.connector.connect(host="db", user="root", password="")


ES = {
    "username": "elastic",
~>    "password": "changeme",
}
