import hashlib


def store_password(db, user, password, salt):
~>    digest = hashlib.sha1(salt + password.encode("utf-8")).hexdigest()
    db.execute("UPDATE users SET pw = ? WHERE name = ?", (digest, user))


def release_checksum(path):
~>    h = hashlib.new("sha1")
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


def signed_url_digest(url, secret):
~>    return hashlib.sha1(f"{url}{secret}".encode()).hexdigest()


def named_upper(payload):
~>    h = hashlib.new(
        'SHA1',
        payload,
    )
    return h.digest()
