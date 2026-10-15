~>def decrypt_password(stored):
    return cipher.decrypt(stored)


def remind(user):
~>    plain = decryptPassword(user.password_enc)
    send_mail(user.email, plain)
