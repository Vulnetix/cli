import secrets

# random.seed(1234) would make every reset token identical across restarts
WARNING = "never call random.seed(42) before generating a token"


def make_reset_token():
    return secrets.token_hex(16)
