import paramiko


class PinnedPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, fingerprints):
        self.fingerprints = fingerprints

    def missing_host_key(self, client, hostname, key):
        if key.get_fingerprint().hex() not in self.fingerprints:
            raise paramiko.SSHException(f"unknown host key for {hostname}")
        client.get_host_keys().add(hostname, key.get_name(), key)
