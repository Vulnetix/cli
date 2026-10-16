import random
import string


def create(db, name):
~>    db.insert(name=name, password=''.join(random.choice(string.ascii_letters) for _ in range(12)))
    payload = {
~>        "csrf_token": random.random(),
        "name": name,
    }
    return payload
