import logging

from django.core.exceptions import PermissionDenied

log = logging.getLogger(__name__)


def has_permission(user, resource):
    try:
        return resource.acl.allows(user)
    except Exception:
        log.exception("permission check failed")
        return False


def check_access(user, doc):
    try:
        return doc.owner_id == user.id
    except Exception as exc:
        raise PermissionDenied() from exc


def verify_signature(payload, sig, key):
    try:
        key.verify(sig, payload)
    except Exception:
        return False
    return True
