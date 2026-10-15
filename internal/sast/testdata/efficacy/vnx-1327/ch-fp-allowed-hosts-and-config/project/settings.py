import os

ALLOWED_HOSTS = ["0.0.0.0", "localhost"]
BIND = os.getenv("BIND_ADDR", "127.0.0.1:8000")
