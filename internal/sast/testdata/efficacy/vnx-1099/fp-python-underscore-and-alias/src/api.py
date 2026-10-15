import warnings


def _fetch(url):
    return url


def fetch(url):
    return _fetch(url)


def current_thread():
    return 1


def currentThread():
    warnings.warn("use current_thread", DeprecationWarning)
    return current_thread()


def load_config(path):
    return path


def loadConfigFile(path):
    return path
