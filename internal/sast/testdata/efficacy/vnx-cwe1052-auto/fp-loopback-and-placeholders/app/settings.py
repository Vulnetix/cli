import os

import psycopg2
import redis

DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://app@db.acme.io/app")


def local_db():
    return psycopg2.connect(host="localhost", port=5432, dbname="dev")


cache = redis.Redis(host="127.0.0.1", port=6379)
docs_example = redis.Redis(host="redis.example.com", port=6379)
compose = psycopg2.connect(host="db", dbname="dev")
listen = redis.Redis(host="0.0.0.0")
