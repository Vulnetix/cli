import json
import os

from django.conf import settings

STATIC_DIR = settings.STATIC_ROOT


def export_connection_settings():
    db = settings.DATABASES["default"]
    target = os.path.join(STATIC_DIR, "db-settings.json")
    with open(target, "w") as fh:
~>        json.dump({"host": db["HOST"], "user": db["USER"], "password": db["PASSWORD"]}, fh)
