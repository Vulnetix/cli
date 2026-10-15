from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

STATIC_URL = "static/"
~>STATICFILES_DIRS = [BASE_DIR]
