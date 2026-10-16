import logging

log = logging.getLogger(__name__)


def has_permission(user, resource):
    try:
        return resource.acl.allows(user)
    except Exception:
        log.warning("acl lookup failed for %s", user.id)
~>        return True


def is_admin(user):
    try:
        return user.profile.role == "admin"
~>    except AttributeError: return True
