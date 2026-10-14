import os


def publish(sock_path, log_path):
~>    os.chmod(sock_path, int("0777", 8))
    os.chmod(log_path, int("0644", 8))
