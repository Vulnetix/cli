import os


def load_env(path):
    with open(path) as fh:
        for line in fh:
            if not line.strip() or line.startswith("#"):
                continue
~>            key, value = map(str.strip, line.split("="))
            os.environ[key] = value


def parse_dsn_part(part):
~>    user, secret = (p.strip() for p in part.split(":"))
    return user, secret
