import logging

log = logging.getLogger(__name__)


def is_authorized(user, resource):
    try:
        return opa_client.check(user.id, resource)
    except Exception as exc:
        log.warning("policy check failed: %s", exc)
~>        return True


def check_token(token):
    try:
        decode(token)
~>    except: return True
    return False
