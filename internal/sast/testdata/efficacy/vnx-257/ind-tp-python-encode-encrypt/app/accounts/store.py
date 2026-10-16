import base64

from cryptography.fernet import Fernet
from django.conf import settings

from .models import Account


def save_account(username, password):
    account = Account(username=username)
~>    account.password = base64.b64encode(password.encode()).decode()
    account.save()


def remember_credentials(user, password):
    f = Fernet(settings.CREDENTIAL_KEY)
~>    user.vault_entry = f.encrypt(password.encode("utf-8"))
    user.save()
