import os


def install_key(path, material):
    old = os.umask(0o077)
    try:
        with open(path, "w") as fh:
            fh.write(material)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    os.chmod(path + ".pub", 0o644)
