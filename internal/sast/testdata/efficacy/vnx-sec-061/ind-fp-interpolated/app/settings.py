import os

DATABASE_URL = f"postgresql://{os.environ['PGUSER']}:{os.environ['PGPASSWORD']}@db:5432/app"
FROM_SHELL = "postgres://app:${DB_PASS}@db.prod.acme.io/app"
TEMPLATE = "postgres://app:%s@db.prod.acme.io/app" % os.environ["P"]
DEFAULTS = "postgres://postgres:postgres@db.prod.acme.io/app"
NOPASS = "postgresql://app@db.prod.acme.io/app"
