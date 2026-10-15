from bottle import redirect, route, request


@route("/admin")
def admin():
    if not request.get_cookie("admin"):
        redirect("/login")
    return "secret"
