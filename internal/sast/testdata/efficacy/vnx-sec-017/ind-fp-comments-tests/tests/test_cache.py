import redis

def test_connect():
    r = redis.from_url("redis://:pw@cache.staging.acmecorp.net:6379/0")
    assert r.ping()
