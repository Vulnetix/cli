import os


def write_profile(access_key, secret_key):
    path = os.path.expanduser("~/.aws/credentials")
    os.makedirs(os.path.dirname(path), exist_ok=True)
~>    with open(path, "w") as fh:
        fh.write("[default]\n")
        fh.write(f"aws_access_key_id = {access_key}\n")
        fh.write(f"aws_secret_access_key = {secret_key}\n")
