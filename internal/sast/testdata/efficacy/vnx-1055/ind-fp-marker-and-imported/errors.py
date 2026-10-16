import requests
from lib import Store, Cache


class ConnectionFailed(Exception):
    pass


class TimedOut(Exception):
    pass


class ConnectTimeout(ConnectionFailed, TimedOut):
    pass


class Both(Store, Cache):
    def x(self):
        return 1
