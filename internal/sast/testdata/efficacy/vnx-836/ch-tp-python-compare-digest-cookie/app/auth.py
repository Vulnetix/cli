import hmac

from flask import abort, request

from .models import Member


def require_member():
    member = Member.query.filter_by(name=request.cookies.get("member")).first()
    token = request.cookies.get("auth")
~>    if member is None or not hmac.compare_digest(member.pw_hash, token):
        abort(401)
    return member
