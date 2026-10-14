from .models import User
from .repository import save


def create_user(name):
    return save(User(name=name))
