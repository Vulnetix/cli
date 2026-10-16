import os


def remove_upload(path, conn):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    try:
        conn.close()
    except:  # noqa: E722
        pass
