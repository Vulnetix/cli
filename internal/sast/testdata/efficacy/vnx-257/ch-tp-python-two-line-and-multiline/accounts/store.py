import base64

from cryptography.fernet import Fernet

fernet = Fernet(settings.PASSWORD_KEY)


def save_user(username, user_password):
    data = user_password.encode("utf-8")
~>    token = fernet.encrypt(data)
    db.users.insert_one({"username": username, "password": token})


def remember(form):
    blob = base64.b64encode(
~>        form.password.encode()
    )
    cache.set(form.username, blob)
