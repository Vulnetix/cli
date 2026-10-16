from .base import *  # noqa

DEBUG = False
ALLOWED_HOSTS = ["portal.acme-corp.com"]

# Temporarily relaxed while the SMS provider migration finishes.
~>MFA_ENABLED = False
SESSION_COOKIE_SECURE = True
