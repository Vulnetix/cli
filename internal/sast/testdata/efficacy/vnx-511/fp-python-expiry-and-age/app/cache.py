import os
import time
import warnings
from datetime import datetime, timedelta

MAX_AGE = 86400


def prune(entries, cert):
    for path in entries:
        if time.time() - os.path.getmtime(path) > MAX_AGE:
            os.remove(path)
    if datetime.now() > cert.not_valid_after:
        raise RuntimeError("certificate expired")
    if datetime.now() > datetime(2026, 1, 1):
        warnings.warn("legacy cache format is deprecated", DeprecationWarning)
    cutoff = datetime.now() - timedelta(days=30)
    return cutoff
