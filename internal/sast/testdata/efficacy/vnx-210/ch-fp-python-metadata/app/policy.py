MIN_PASSWORD_LENGTH = 12


def check(password, token_type, secret_name):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must have {MIN_PASSWORD_LENGTH} characters, got {len(password)}")
    if token_type not in ("bearer", "mac"):
        raise ValueError(f"unsupported token type {token_type}")
    if not secret_name:
        raise KeyError("secret name is required")
    raise PermissionError("credentials rejected for this tenant")
