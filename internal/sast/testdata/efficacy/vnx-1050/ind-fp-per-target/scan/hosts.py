import psycopg2
import redis


def collect(hosts, shards):
    for host in hosts:
        conn = psycopg2.connect(host=host, dbname="metrics")
        conn.close()
    for shard in shards:
        r = redis.Redis(host=shard.addr, port=shard.port)
        r.ping()
    for url in urls:
        c = redis.from_url(url)
        c.ping()
