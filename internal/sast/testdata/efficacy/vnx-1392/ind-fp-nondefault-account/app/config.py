DATABASE_URL = "postgres://app:app@db:5432/app"
REPORT_URL = "postgres://ops:changeme@db:5432/reports"
STRONG = "postgres://postgres:" + os.environ["PGPASS"] + "@db/app"
