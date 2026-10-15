from flask import redirect, request, session


def enter_admin():
    ref = request.headers.get("Referer", "")
~>    if ref.startswith("https://intranet.acme.example/"):
        session["admin"] = True
        return redirect("/admin")
    return redirect("/")
