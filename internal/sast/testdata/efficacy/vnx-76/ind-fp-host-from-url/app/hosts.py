def host_of(url):
    host = url.replace("https://", "").replace("http://", "")
    return host.split("/", 1)[0]


def tidy(name):
    return name.replace("-", "_").replace(".", "")
