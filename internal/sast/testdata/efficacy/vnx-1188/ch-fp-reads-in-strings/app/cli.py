import os

HELP = "Set DEBUG with os.environ.get('DEBUG', 'True') during development only"
USAGE = 'export VERIFY_SSL=0  # equivalent to os.getenv("VERIFY_SSL", "0")'


def debug_enabled():
    return os.environ.get("DEBUG", "false").lower() == "true"
