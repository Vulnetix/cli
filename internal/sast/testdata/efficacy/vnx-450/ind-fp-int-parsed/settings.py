import os

DEBUG = bool(int(os.environ.get("DEBUG", "0")))
ENABLE_CACHE = bool(int(os.getenv("ENABLE_CACHE", "1")))
WORKERS = int(os.environ.get("WORKERS", "4"))
