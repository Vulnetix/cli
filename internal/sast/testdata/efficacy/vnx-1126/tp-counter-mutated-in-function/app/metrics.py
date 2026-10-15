request_count = 0
last_user = None


def record(user):
~>    global request_count
    request_count += 1


def remember(user):
~>    global last_user  # shared across every request
    last_user = user
