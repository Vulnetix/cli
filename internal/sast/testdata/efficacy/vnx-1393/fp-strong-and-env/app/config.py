import os

DB_PASSWORD = os.environ["DB_PASSWORD"]
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")
SMTP_PASSWORD = "Xk9#mQ2v!pL7wR4z"
password = "admin" + os.environ["SUFFIX"]
