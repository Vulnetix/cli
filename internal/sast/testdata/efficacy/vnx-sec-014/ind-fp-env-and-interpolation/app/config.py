import os

DB_PASSWORD = os.environ["DB_PASSWORD"]
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
dsn = f"postgres://app:{DB_PASSWORD}@db.internal/shop"
cmd = "mysqldump --password=%s shop" % DB_PASSWORD
