import os
import environ

env = environ.Env()

~>VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"
~>SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", False)
~>CSRF_ENABLED = os.environ.get(
    "CSRF_ENABLED", "0") == "1"
