import hashlib


def store_password(db, user, password):
~>    digest = hashlib.md5(password.encode("utf-8")).hexdigest()
    db.execute("UPDATE users SET pw = ? WHERE name = ?", (digest, user))


def reset_token(email, issued_at):
~>    return hashlib.md5(f"{email}:{issued_at}".encode()).hexdigest()


def file_checksum(path):
~>    h = hashlib.new("md5")
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def signature_for(payload):
~>    h = hashlib.new(
        'MD5',
        payload,
    )
    return h.hexdigest()


def legacy_digest(data):
~>    return hashlib.md5 (data).digest()
