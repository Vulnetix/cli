def is_json(content_type):
~>    if content_type.find("json"):
        return True
    return False


def has_port(host):
~>    return True if host.rfind(":") else False


def scan(lines):
    out = []
    for line in lines:
~>        if line.strip() and line.lower().find("error"):
            out.append(line)
    return out
