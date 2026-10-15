import datetime


def check(request):
    try:
        cookie = request.COOKIES["session"]
        expire = cookie.split("|")[1]
        return datetime.datetime.fromisoformat(expire)
    except (KeyError, IndexError, ValueError):
        return None
