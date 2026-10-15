# Never do this: resp.set_cookie("is_admin", "1") or request.cookies.get("role")
HELP = 'Do not call request.cookies.get("role") to authorise; use the session.'


def explain():
    """
    response.set_cookie("admin", "1") lets the client grant itself admin.
    """
    return HELP
