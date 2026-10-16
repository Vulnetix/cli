import hmac


def bearer(request):
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        return token[len("Bearer "):]
    return None


def full_compare(a_digest, b_digest):
    return hmac.compare_digest(a_digest, b_digest)


def is_python_file(path):
    return path.endswith(".py")


def key_ok(key, TOKEN_PREFIX):
    return key.startswith(TOKEN_PREFIX)


# stored_key.startswith(provided) would be wrong here
