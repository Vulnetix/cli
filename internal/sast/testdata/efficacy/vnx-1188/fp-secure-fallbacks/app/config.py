import os
from decouple import config

DEBUG = False
DEBUG = os.getenv("DEBUG", "False") == "True"
TEMPLATE_DEBUG = config("TEMPLATE_DEBUG", default=False, cast=bool)
VERIFY_SSL = os.environ.get("VERIFY_SSL", True)
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true") == "true"
LOG_LEVEL = os.getenv("LOG_LEVEL", "debug")
DEBUG_TOOLBAR_PORT = os.environ["DEBUG_PORT"]
# DEBUG = os.environ.get("DEBUG", True)
HELP = 'set DEBUG = True only on your laptop'
