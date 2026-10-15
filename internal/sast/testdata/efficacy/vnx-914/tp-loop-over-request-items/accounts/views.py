import json


def edit(request, user):
    payload = json.loads(request.body)
    for key, value in payload.items():
~>        setattr(user, key, value)
    user.save()
