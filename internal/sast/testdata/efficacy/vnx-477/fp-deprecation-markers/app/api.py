import warnings


def old_fetch(url):
    warnings.warn("Deprecated: use fetch()", DeprecationWarning, stacklevel=2)
    return fetch(url)


def fetch(url):
    return url
