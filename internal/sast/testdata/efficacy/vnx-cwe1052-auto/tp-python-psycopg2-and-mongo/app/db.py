import psycopg2
import redis
from pymongo import MongoClient


def connect(user, password):
    return psycopg2.connect(
~>        host="172.16.8.20",
        port=5432,
        dbname="billing",
        user=user,
        password=password,
    )


~>events = MongoClient("mongodb://mongo-0.data.acme.io:27017/?replicaSet=rs0")
~>cache = redis.Redis(host='redis.prod.acme.io', port=6379, db=2)
~>queue = redis.StrictRedis("10.4.0.9", 6380)
