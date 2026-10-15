import os
from decouple import config
import environ

env = environ.Env()

~>WEB_DEBUG = os.environ.get('WEB_DEBUG', True)
~>DEBUG = os.getenv("DJANGO_DEBUG", "1") == "1"
~>TEMPLATE_DEBUG = config("TEMPLATE_DEBUG", default=True, cast=bool)
~>ALLOW_INSECURE = env.bool("ALLOW_INSECURE", default=True)
~>debug_mode = str(os.environ.get("APP_DEBUG", "true")).lower() in ("1", "true")
