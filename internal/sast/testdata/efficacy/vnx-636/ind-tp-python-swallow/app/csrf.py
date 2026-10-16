import hmac


def verify_csrf(request, secret):
    try:
        expected = hmac.new(secret, request.session["sid"].encode(), "sha256").hexdigest()
        if not hmac.compare_digest(expected, request.form["csrf_token"]):
            return False
    except KeyError:
        pass
~>    return True
