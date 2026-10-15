import functools

import redis

r = redis.Redis()


~>@functools.lru_cache(maxsize=256)
def check_credentials(username, password):
    return ldap_bind(username, password)


def remember(request):
    raw_password = request.POST["password"]
~>    r.setex(f"pending:{request.user.id}", 300, raw_password)
