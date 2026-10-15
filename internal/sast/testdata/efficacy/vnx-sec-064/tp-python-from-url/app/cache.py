import redis

~>r = redis.from_url("redis://worker:@@sample:[A-Za-z0-9]{20}@@@10.0.5.9:6379/2")
