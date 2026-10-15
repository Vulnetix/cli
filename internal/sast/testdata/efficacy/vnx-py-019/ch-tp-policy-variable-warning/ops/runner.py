from paramiko import SSHClient, WarningPolicy


class Runner:
    def __init__(self, host):
        self.client = SSHClient()
        policy = WarningPolicy()
~>        self.client.set_missing_host_key_policy(policy)
        self.client.connect(host)
