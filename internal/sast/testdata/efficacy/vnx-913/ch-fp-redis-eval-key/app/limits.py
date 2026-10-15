from flask import request
import redis

r = redis.Redis()
INCR_SCRIPT = "return redis.call('INCR', KEYS[1])"


def bump():
    user = request.args.get("user")
    return r.eval(INCR_SCRIPT, 1, user)
