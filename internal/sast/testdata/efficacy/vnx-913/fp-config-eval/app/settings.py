import os


def setting():
    raw = os.environ.get("RETRIES", "3")
    return eval(raw)
