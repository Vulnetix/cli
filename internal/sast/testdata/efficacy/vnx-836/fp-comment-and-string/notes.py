# Never do: if user.password_hash == request.form["password_hash"]
HELP = 'if user.password_hash == request.form["password_hash"] is pass-the-hash'


def describe():
    return HELP
