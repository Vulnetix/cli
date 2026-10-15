import os


def save_api_key(api_key, path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(api_key)


def store_token(token, token_file):
    with open(token_file, "w") as f:
        f.write(token)
    os.chmod(token_file, 0o600)


def read_token(token_file):
    with open(token_file, "r") as f:
        return f.read()
