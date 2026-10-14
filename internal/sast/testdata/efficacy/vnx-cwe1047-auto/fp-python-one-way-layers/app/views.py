from app.services import create_user
from app import models


def signup(request):
    return create_user(request.form["name"])
