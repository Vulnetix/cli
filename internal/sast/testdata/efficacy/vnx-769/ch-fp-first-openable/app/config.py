CANDIDATES = ["/etc/acme.conf", "~/.acme.conf"]


def read_config():
    fh = None
    for cand in CANDIDATES:
        try:
            fh = open(cand)
        except OSError:
            continue
        break
    if fh is None:
        return ""
    with fh:
        return fh.read()
