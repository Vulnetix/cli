import os
import socket


def serve(name):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
~>    s.bind(f"/tmp/{name}.sock")
    s.listen(1)
    return s


def fifo(job_id):
~>    os.mkfifo("/var/tmp/job-%s.fifo" % job_id, 0o600)
