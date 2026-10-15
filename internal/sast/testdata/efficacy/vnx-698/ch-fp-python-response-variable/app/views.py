from flask import redirect, url_for, make_response


def logout():
    response = redirect(url_for("index"))
    response.delete_cookie("session")
    return response


def go_home():
    return redirect(
        url_for("index")
    )
