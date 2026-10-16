import os

import sentry_sdk

SENTRY_DSN = os.environ.get("SENTRY_DSN")
HAS_SENTRY = bool(SENTRY_DSN)
HAS_REDIS = bool(os.getenv("REDIS_URL"))
API_TOKEN_SET = bool(os.environ.get("API_TOKEN"))

if HAS_SENTRY:
    sentry_sdk.init(dsn=SENTRY_DSN)
