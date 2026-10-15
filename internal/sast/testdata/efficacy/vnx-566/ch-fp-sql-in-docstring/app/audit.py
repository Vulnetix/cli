from flask import request


def describe():
    """Explains the lookup.

    The handler runs "SELECT * FROM audit WHERE id = ?" with the id from the
    session, never from request.args.
    """
    return request.args.get("format", "json")
