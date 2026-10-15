import os

DEBUG_TOOLBAR_CONFIG = {
    "SHOW_TOOLBAR_CALLBACK": lambda request: DEBUG and request.META.get("REMOTE_ADDR") in INTERNAL_IPS,
}
INTERNAL_IPS = ["127.0.0.1"]
