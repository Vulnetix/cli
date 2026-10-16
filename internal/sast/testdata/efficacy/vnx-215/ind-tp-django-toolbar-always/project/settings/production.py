from .base import *  # noqa: F401,F403

DEBUG = False
ALLOWED_HOSTS = ["shop.example.com"]

INSTALLED_APPS += ["debug_toolbar"]
MIDDLEWARE += ["debug_toolbar.middleware.DebugToolbarMiddleware"]

DEBUG_TOOLBAR_CONFIG = {
~>    "SHOW_TOOLBAR_CALLBACK": lambda request: True,
}
