import redis
import psycopg2
from pymongo import MongoClient


def flush_all(hosts):
    for host in hosts:
        client = redis.Redis(host=host, port=6379)
        client.flushdb()


def check_shards(shards):
    for shard in shards:
        dsn = shard["dsn"]
        conn = psycopg2.connect(dsn)
        conn.close()


def ping(uris):
    for uri in uris:
        MongoClient(uri).admin.command("ping")
