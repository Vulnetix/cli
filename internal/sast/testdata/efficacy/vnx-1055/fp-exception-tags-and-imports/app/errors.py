from requests import Session
from collections import OrderedDict


class ServiceError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class ConnectionFailed(ServiceError):
    """The upstream could not be reached."""


class TimedOut(ServiceError):
    pass


class ConnectTimeout(ConnectionFailed, TimedOut):
    """Raised when connecting times out."""


class BadInput(ServiceError, ValueError):
    pass


class OrderedSession(Session, OrderedDict):
    pass
