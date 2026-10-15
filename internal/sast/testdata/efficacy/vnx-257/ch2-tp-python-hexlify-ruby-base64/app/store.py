import binascii


def remember(user, password):
~>    user.secret_blob = binascii.hexlify(password.encode("utf-8"))
    user.save()
