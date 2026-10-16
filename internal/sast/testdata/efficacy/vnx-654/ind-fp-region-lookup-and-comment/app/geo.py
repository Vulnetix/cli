from flask import request, g


def tag_region():
    # if request.remote_addr == "127.0.0.1": return True
    if request.remote_addr.startswith("192.168."):
        g.region = "lan"
    msg = 'if request.remote_addr == "127.0.0.1": return True'
    return msg


def limited():
    if request.remote_addr in RATE_LIMITED:
        return False
    return None
