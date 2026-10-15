import random


def login(request, words):
~>    request.session["csrf_token"] = str(random.random())
~>    user = User(username="guest", password=random.choice(words))
    return user
