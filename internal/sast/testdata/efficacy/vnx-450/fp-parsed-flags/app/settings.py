import os
from distutils.util import strtobool

DEBUG = os.environ.get("APP_DEBUG", "false").lower() in ("1", "true", "yes")
REQUIRE_TLS = os.getenv("REQUIRE_TLS", "1") == "1"
ALLOW_SIGNUP = bool(strtobool(os.environ.get("ALLOW_SIGNUP", "false")))
WORKERS = int(os.environ.get("WORKERS", 4))
HAS_TOKEN = bool(os.environ.get("API_TOKEN"))
SENTRY_ON = bool(os.getenv("SENTRY_DSN"))
proxy_set = bool(os.environ.get("HTTPS_PROXY_URL"))
SKIP = os.environ.get("SKIP_AUTH", "false")
PORT = os.environ.get("PORT", 8080)


def is_enabled(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def has_rows(rows):
    return bool(rows)
