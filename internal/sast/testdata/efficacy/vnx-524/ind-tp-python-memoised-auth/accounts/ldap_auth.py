import functools

import ldap
from cachetools import TTLCache, cached

LDAP_URL = "ldaps://directory.acme-corp.com"


~>@functools.lru_cache(maxsize=1024)
def check_credentials(username: str, password: str) -> bool:
    conn = ldap.initialize(LDAP_URL)
    try:
        conn.simple_bind_s(f"uid={username},ou=people,dc=acme,dc=com", password)
        return True
    except ldap.INVALID_CREDENTIALS:
        return False
    finally:
        conn.unbind_s()


~>@cached(cache=TTLCache(maxsize=256, ttl=300))
def service_login(client_id, client_password):
    return check_credentials(client_id, client_password)
