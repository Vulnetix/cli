import hmac


def classify(api_key: str) -> str:
    if api_key.startswith("sk_live_"):
        return "live"
    if api_key.startswith("sk_test_"):
        return "test"
    return "unknown"


def is_bcrypt(password_hash: str) -> bool:
    return password_hash.startswith(("$2a$", "$2b$", "$2y$"))


def bearer(auth_header: str) -> str:
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        return token
    return ""


def is_key_file(path: str) -> bool:
    return path.endswith(".key") or path.endswith(".pem")


def same(token: str, expected_token: str) -> bool:
    return hmac.compare_digest(token, expected_token)
