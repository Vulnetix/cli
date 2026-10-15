SNIPPET = "s = socket.socket()"


def describe():
    # s = socket.socket()  would leak here
    return SNIPPET
