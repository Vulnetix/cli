import logging
import http.client

~>logging.getLogger().setLevel(logging.DEBUG)
~>http.client.HTTPConnection.debuglevel = 1
~>logging.basicConfig(
    format="%(asctime)s %(message)s",
    level="DEBUG",
)
