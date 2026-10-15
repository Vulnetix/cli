import os


def write_key(key_path, pem):
    with open(key_path, "w") as fh:
        fh.write(pem)
~>    os.chmod(key_path, 0o644)


def ssh(home):
~>    os.chmod(os.path.join(home, ".ssh", "id_rsa"), 0o604)
