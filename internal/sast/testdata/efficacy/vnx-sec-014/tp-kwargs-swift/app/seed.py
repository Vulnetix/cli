from app.models import User


def seed():
    User.create(username="operator",
~>                password="0perat0r-2024!")
