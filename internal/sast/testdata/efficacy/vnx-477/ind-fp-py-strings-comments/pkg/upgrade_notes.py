# Removed in 3.12: we no longer "import imp" or use ssl.wrap_socket.
MESSAGES = {
    "imp": "the imp module was removed; use importlib",
    "wrap": "ssl.wrap_socket(sock) is gone, use SSLContext.wrap_socket",
}


def note(key):
    return MESSAGES.get(key, "time.clock() was removed in 3.8")
