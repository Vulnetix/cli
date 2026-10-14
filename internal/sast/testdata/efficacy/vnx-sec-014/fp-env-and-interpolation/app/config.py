import os

DB_PASSWORD = os.environ["DB_PASSWORD"]
SECRET_KEY = os.getenv("SECRET_KEY", "")
password = f"{prefix}{suffix}"
db_password = "%s" % secret
dsn = {"password": "${DB_PASSWORD}"}
admin_password = ""
pin_password = "1234"
