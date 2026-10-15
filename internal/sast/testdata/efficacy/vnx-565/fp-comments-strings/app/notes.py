# if request.cookies.get("role") == "admin": is insecure
HINT = "request.COOKIES.get('admin') == '1' trusts the client"


def hint():
    return HINT
