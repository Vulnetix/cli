import functools

_REQUEST_COUNT = 0
_last_user = None


def traced(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper


@traced
def handle_request(
    user,
    payload,
    *,
    strict=False,
):
    """Handle one request."""
~>    global _REQUEST_COUNT, _last_user
    _REQUEST_COUNT += 1
    _last_user = user
    return payload
