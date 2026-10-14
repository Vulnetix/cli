import os

# DEBUG = True
DEBUG = False
if os.environ.get("ENVIRONMENT") == "development":
    DEBUG = True
DEBUG_TOOLBAR = True
SQL_DEBUG = True
NOTE = "set DEBUG = True only on your laptop"
INSTALLED_APPS = ["web"]
