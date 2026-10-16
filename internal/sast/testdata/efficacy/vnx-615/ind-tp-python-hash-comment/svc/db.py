import os


def connect():
~>    # password = "R3port!ng2023"
    return open_conn(password=os.environ["DB_PASSWORD"])
