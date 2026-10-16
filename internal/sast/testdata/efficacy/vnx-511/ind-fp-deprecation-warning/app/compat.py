import warnings
from datetime import date, datetime


def legacy_api():
    if datetime.now() > datetime(2026, 6, 1):
        warnings.warn("legacy_api is deprecated and will be removed", DeprecationWarning)
    if date.today() >= date(2027, 1, 1):
        raise RuntimeError("legacy_api has been removed")
    return True
