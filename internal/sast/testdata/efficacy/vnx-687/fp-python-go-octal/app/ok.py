import os


def ok(base):
    os.makedirs(base, 0o755, exist_ok=True)
    os.chmod(base, 0o600)
    os.makedirs(base, exist_ok=True)
    print("chmod(path, 755)")
    # os.chmod(base, 755) would be decimal
    retries = max(base, 100)
