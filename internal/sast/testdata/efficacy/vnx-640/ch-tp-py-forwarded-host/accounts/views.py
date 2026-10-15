from flask import request, url_for


def forgot_password():
    token = make_token(request.form["email"])
~>    base = request.headers.get("X-Forwarded-Host", request.host)
    reset_link = f"https://{base}/reset/{token}"
    send_mail(request.form["email"], reset_link)
    return "", 204
