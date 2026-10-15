import logging

~>logging.disable(logging.CRITICAL)
~>logging.getLogger("app.security").disabled = True


def start():
~>    logging.disable()
    serve()
