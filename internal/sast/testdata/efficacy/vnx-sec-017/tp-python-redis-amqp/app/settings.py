import redis
import pika

~>CACHE = redis.from_url("redis://cache-user:s3cret@cache.prod.acme.io:6379/0")
~>params = pika.URLParameters('amqp://orders:orderpw@mq.internal.acme.io:5672/%2F')
connection = pika.BlockingConnection(params)
~>CELERY_BROKER_URL = f"amqp://{user}:{pw}@10.20.0.15:5672//"
