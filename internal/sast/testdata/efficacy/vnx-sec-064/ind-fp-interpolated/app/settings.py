import os

REDIS_URL = f"redis://:{REDIS_PASSWORD}@redis:6379/0"
OTHER = "redis://:" + os.environ["REDIS_PASSWORD"] + "@redis.prod.acme.io:6379/0"
SHELL = "redis://:${REDIS_PASSWORD}@redis.prod.acme.io:6379/0"
NOPASS = "redis://redis.prod.acme.io:6379/0"
DEFAULTS = "redis://default:default@redis.prod.acme.io:6379/0"
