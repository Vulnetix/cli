import os

DEBUG = os.environ.get("DEBUG", "False")
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true")
DEBUG_COLORS = os.environ.get("DEBUG_COLORS", "1")
DEBUG_PORT = os.environ.get("DEBUG_PORT", "5678")
API_KEY = os.environ.get("API_KEY")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info")
# VERIFY_SSL = os.environ.get("VERIFY_SSL", "false")
HELP = 'os.environ.get("DEBUG", "true")'
