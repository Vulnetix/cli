import logging

import requests

log = logging.getLogger(__name__)

# Do not call requests.get(url, verify=False) to work around the proxy.
HELP = "Passing verify=False to requests disables certificate checks."


def fetch(url):
    log.warning("someone asked for requests.get(url, verify=False)")
    return requests.get(url, timeout=5)
