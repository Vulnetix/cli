import os
import redis
import psycopg2

~>DB_HOST = "10.20.4.17"
~>CACHE = redis.Redis(host='172.16.8.3', port=6379, db=0)
PORT = int(os.environ.get("PORT", 8000))

def conn():
~>    return psycopg2.connect("postgresql://app@10.20.4.17:5432/orders")
