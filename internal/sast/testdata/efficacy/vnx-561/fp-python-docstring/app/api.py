def handle(value):
    """Convert the value.

    The handler may raise
    an error. In order to convert the return
    value to a response, call make_response.
    """
    return make_response(value)
