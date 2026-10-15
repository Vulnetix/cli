from flask import request


def set_mode():
~>    mode = int(request.args.get("mode"), 0)
    return apply_mode(mode)


def parse_octet(text):
~>    return int(text.strip(), base=0)


def port_from(form):
    raw = form["port"]
~>    port = int(raw,0)
    return port
