import getpass
import os

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
password = getpass.getpass("Password: ")
admin_password = "$2b$12$@@sample:K[q]1p[G]x8[z]W3[v]R5[t]Y7[u]I9[o]Pe@@"
db_password = settings.DATABASES["default"]["PASSWORD"]
PASSWORD_MIN_LENGTH = 12
password_reset_template = "accounts/password_reset.html"
