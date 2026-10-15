import os

DATABASE_URL = f"postgresql://{os.environ['PGUSER']}:{os.environ['PGPASSWORD']}@db:5432/app"
DSN = "postgres://app:${POSTGRES_PASSWORD}@db:5432/app"
DSN2 = "postgres://%s:%s@%s/%s" % (user, pw, host, name)
