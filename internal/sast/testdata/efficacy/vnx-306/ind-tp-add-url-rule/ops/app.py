from flask import Flask

from ops.cache import redis_client

app = Flask(__name__)


def flush_cache():
    redis_client.flushall()
    return "flushed", 200


~>app.add_url_rule("/admin/cache/flush", view_func=flush_cache, methods=["POST"])
