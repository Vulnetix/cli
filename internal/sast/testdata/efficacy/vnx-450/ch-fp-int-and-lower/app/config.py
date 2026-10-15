import os

DEBUG = bool(int(os.environ.get("APP_DEBUG", "0")))
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").strip().lower() in {"1", "true", "yes"}
HAS_SENTRY = bool(os.environ.get("SENTRY_DSN"))
FEATURE_FLAGS = os.environ.get("FEATURE_FLAGS", "").split(",")
