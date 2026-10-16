import logging

import jwt
from django.core.exceptions import PermissionDenied

security_log = logging.getLogger("app.security")


def authenticate(request, token, secret):
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        security_log.info("expired token from %s", request.META.get("REMOTE_ADDR"))
        raise PermissionDenied("token expired")
    except jwt.InvalidTokenError:
        security_log.warning("rejected token from %s", request.META.get("REMOTE_ADDR"))
        return None
