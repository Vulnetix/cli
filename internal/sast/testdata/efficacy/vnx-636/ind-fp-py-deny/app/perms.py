import logging

log = logging.getLogger(__name__)


def has_permission(user, resource):
    try:
        return resource.acl.allows(user)
    except Exception:
        log.exception("permission check failed")
        return False


def check_token(t):
    try:
        return decode(t)
    except Exception as e:
        raise PermissionError("bad token") from e
