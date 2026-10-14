import paramiko


class TrustEverything(paramiko.MissingHostKeyPolicy):
~>    def missing_host_key(self, client, hostname, key):
        pass


class Quiet(paramiko.MissingHostKeyPolicy):
~>    def missing_host_key(self, client, hostname, key):
        # accept silently
        return
