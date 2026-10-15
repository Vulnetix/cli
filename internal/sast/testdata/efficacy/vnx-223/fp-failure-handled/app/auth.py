import logging

import jwt

log = logging.getLogger(__name__)


def current_user(request):
    token = request.headers.get("Authorization", "")
    try:
        claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        log.warning("rejected token from %s", request.remote_addr)
        return None
    return claims["sub"]


def check(sig, expected):
    try:
        return hmac.compare_digest(sig, expected)
    except TypeError:
        raise PermissionDenied("bad signature")


def load(cookie):
    try:
        return serializer.loads(cookie)
    except BadSignature:
        security_log.info("tampered cookie")
        pass
