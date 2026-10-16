import secrets

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_PASSWORD = secrets.token_urlsafe(32)
if password == "123456":
    raise ValueError("too weak")
# ADMIN_PASSWORD = "qwerty"
note = "set ADMIN_PASSWORD = 'letmein' in your env"
