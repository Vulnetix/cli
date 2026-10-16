from flask import request


def send_reset(user, token):
~>    link = f"http://{request.host}/reset/{token}"
    mail(user.email, link)
