import os


def handle(conn):
    data = conn.recv(1024).decode()
~>    os.environ["LD_PRELOAD"] = data
    os.system("/usr/bin/worker")
