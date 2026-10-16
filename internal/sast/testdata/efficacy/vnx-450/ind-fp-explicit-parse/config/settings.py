import os
from distutils.util import strtobool

DEBUG = os.environ.get("APP_DEBUG", "false").strip().lower() in {"1", "true", "yes", "on"}
VERIFY_TLS = bool(strtobool(os.getenv("VERIFY_TLS", "true")))
ENABLE_SIGNUP = os.getenv("ENABLE_SIGNUP") == "1"
FEATURE_SEARCH = os.environ.get("FEATURE_SEARCH", "off")
