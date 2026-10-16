import os

from app.authz import has_permission
from app.config import settings


def export_dir(user):
    base = settings.EXPORT_ROOT
    if not has_permission(user, base):
        raise PermissionError("export disabled for this account")
    return os.path.realpath(base)
