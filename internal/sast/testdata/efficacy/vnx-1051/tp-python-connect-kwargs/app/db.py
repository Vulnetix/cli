import psycopg2
import redis
import requests

~>DB_HOST = "10.20.4.17"
~>CACHE = redis.Redis(host='172.16.8.3', port=6379, db=0)


def connect():
    return psycopg2.connect(
~>        host="10.20.4.18",
        dbname="orders",
        user="app",
    )


def fetch_inventory():
~>    resp = requests.get(f"http://10.20.4.40:8080/api/inventory", timeout=5)
    return resp.json()
