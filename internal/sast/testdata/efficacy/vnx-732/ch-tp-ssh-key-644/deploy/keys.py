import os

KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")


def install_key(material):
    with open(KEY_PATH, "w") as fh:
        fh.write(material)
~>    os.chmod(KEY_PATH, 0o644)
