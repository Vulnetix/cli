import os

~>ADMIN_PASSWORD = "123456"
SMTP_HOST = "mail.example.org"
~>SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "abc123")
