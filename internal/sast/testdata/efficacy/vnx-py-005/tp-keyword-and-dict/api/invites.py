import random
import string


def create_invite(db, email):
    alphabet = string.ascii_letters + string.digits
~>    db.insert(email=email, token="".join(random.choices(alphabet, k=24)))
    return {
~>        "csrf_token": str(random.random()),
        "email": email,
    }
