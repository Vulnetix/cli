from paramiko import SSHClient, AutoAddPolicy
from paramiko.client import WarningPolicy


def run(host, cmd):
    client = SSHClient()
    policy = AutoAddPolicy()
~>    client.set_missing_host_key_policy(policy)
    client.connect(host)
    return client.exec_command(cmd)


def run2(host):
    client = SSHClient()
~>    client.set_missing_host_key_policy(
        WarningPolicy()
    )
    client.connect(host)
