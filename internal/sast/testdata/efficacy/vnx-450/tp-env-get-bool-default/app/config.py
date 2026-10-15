import os
from os import environ

WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
~>WEB_DEBUG = os.environ.get("WEB_DEBUG", True)
~>ENFORCE_CSRF = os.getenv('ENFORCE_CSRF', False)
~>SKIP_AUTH = environ.get("SKIP_AUTH",False)


class Settings:
~>    verify_ssl = os.environ.get(
        "VERIFY_SSL", True)
