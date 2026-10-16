def basename(url):
    return url[url.rfind("/") + 1:]


def key_value(pair):
    idx = pair.find("=")
    if idx == -1:
        return pair, ""
    return pair[:idx], pair[idx + 1:]


def after_colon(line):
    if ":" in line:
        return line[line.find(":") + 1:]
    return line
