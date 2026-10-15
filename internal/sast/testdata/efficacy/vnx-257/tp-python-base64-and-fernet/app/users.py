import base64
from cryptography.fernet import Fernet


def save(user, password):
~>    user.password = base64.b64encode(password.encode()).decode()
~>    token = Fernet(settings.KEY).encrypt(password.encode())
~>    user.secret = cipher.encrypt( pad(user.password.encode(), 16) )
    db.session.commit()
