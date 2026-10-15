import jwt
from cryptography.hazmat.primitives import hashes


def peek(token):
    return jwt.decode(token, options={"verify_signature": False})


def check(form):
    form.verify_email = False
    send_mail(to=form.email, verify_link=False)
    return verify_password(form.password, verify=False if form.legacy else True)


def send_mail(to, verify_link):
    pass


def verify_password(pw, verify):
    return verify
