import os

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
~>        "LOCATION": "redis://:s3cretPw@cache.prod.acmecorp.net:6379/1",
    }
}

CELERY_TIMEOUT = int(os.environ.get("CELERY_TIMEOUT", 30))
