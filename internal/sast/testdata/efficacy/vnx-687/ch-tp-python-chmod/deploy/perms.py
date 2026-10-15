import os


def secure(path, d):
~>    os.chmod(path, 644)
~>    os.makedirs(d, mode=755, exist_ok=True)
