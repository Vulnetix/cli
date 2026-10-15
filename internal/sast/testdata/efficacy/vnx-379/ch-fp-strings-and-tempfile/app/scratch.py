import tempfile

HELP = 'never call open("/tmp/x", "w") or os.makedirs(d, 0o777)'


def scratch(data: bytes):
    # os.chmod("/tmp/x", 0o777) would expose it
    with tempfile.NamedTemporaryFile(dir="/tmp", delete=False) as fh:
        fh.write(data)
    with tempfile.TemporaryDirectory(dir="/var/tmp") as d:
        print(d)
    fd, name = tempfile.mkstemp(prefix="up-", dir="/tmp")
    return name
