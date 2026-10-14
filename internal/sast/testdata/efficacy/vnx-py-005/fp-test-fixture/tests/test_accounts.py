import random
import string


def test_login_rejects_wrong_password(client):
    password = "".join(random.choices(string.ascii_letters, k=12))
    token = random.randint(0, 10**6)
    assert client.login("alice", password, token).status_code == 401
