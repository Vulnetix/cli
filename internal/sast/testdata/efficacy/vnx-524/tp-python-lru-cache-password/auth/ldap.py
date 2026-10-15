import functools
from functools import lru_cache


~>@functools.lru_cache(maxsize=1024)
def check_credentials(username: str, password: str) -> bool:
    return ldap_bind(username, password)


~>@lru_cache
@log_calls
def verify(user,
           raw_password):
    return backend.verify(user, raw_password)
