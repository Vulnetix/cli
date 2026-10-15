import logging

import paramiko

log = logging.getLogger(__name__)


class LoggingPolicy(paramiko.MissingHostKeyPolicy):
~>    def missing_host_key(self, client, hostname, key):
        log.warning("accepting unknown host key for %s", hostname)
        client.get_host_keys().add(hostname, key.get_name(), key)


class OneLiner(paramiko.MissingHostKeyPolicy):
~>    def missing_host_key(self, client, hostname, key): pass
