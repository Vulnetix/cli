import paramiko


class FingerprintPolicy(paramiko.MissingHostKeyPolicy):
    def missing_host_key(
        self, client, hostname, key
    ):
        expected = self.pins.get(hostname)
        if expected != key.get_fingerprint():
            raise paramiko.BadHostKeyException(hostname, key, expected)


class Fallback(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        log_attempt(hostname)
        return paramiko.RejectPolicy().missing_host_key(client, hostname, key)
