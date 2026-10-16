ALLOWED = {"first_name", "last_name"}

def patch(user):
    for key, value in request.get_json().items():
        if key not in ALLOWED:
            continue
        setattr(user, key, value)
