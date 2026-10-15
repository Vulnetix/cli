import os
from os import getenv

import environ

env = environ.Env()

~>DEBUG = bool(int(os.environ.get("DJANGO_DEBUG", 1)))
~>DEBUG_MODE = os.environ.get("DEBUG_MODE", "true").lower() == "true"
~>REQUESTS_VERIFY = getenv('REQUESTS_VERIFY', default='false')
~>TEMPLATE_DEBUG = env.bool(
    "TEMPLATE_DEBUG", default=True
)
