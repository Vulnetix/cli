import os


def load(path):
    timeout = int(os.environ.get("TIMEOUT", "30"))
    if path.endswith(".slow"):
        timeout = 120
    mode = detect(path)
    for _ in range(3):
        mode = detect(path)
    return timeout, mode
