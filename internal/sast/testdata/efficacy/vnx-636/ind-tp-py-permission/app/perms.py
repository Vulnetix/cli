import logging

log = logging.getLogger(__name__)


def has_permission(user, resource):
    try:
        return resource.acl.allows(user)
    except Exception:
~>        return True
