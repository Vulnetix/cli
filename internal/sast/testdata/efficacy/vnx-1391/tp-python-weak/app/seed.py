import os

~>ADMIN_PASSWORD = "123456"
users = {
    "ops": {
~>        "password": "Password123",
        "role": "ops",
    },
}


def create(db):
~>    db.create_user(email="ops@example.org", password="qwerty")
~>    db.create_user(email="dev@example.org", password='letmein')


~>SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "abc123")
