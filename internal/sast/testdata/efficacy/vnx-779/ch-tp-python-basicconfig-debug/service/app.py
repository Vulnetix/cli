import logging
import http.client

~>logging.basicConfig(level=logging.DEBUG)
~>http.client.HTTPConnection.debuglevel = 1
