import hashlib
import time

from .models import ApiCredential


def issue_api_key(user):
~>    api_key = hashlib.sha1(f"{user.id}:{user.email}:{time.time()}".encode()).hexdigest()
    ApiCredential.objects.create(user=user, key=api_key)
    return api_key
