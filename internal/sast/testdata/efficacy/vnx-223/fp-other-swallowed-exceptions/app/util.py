import os


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def parse(value):
    try:
        return int(value)
    except ValueError:
        pass
    return None


def close(conn):
    try:
        conn.close()
    except Exception:
        pass
