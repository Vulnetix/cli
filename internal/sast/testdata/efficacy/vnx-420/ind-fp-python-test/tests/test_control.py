import os
import socket


def test_world_writable_socket(tmp_path):
    path = str(tmp_path / "c.sock")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o666)
