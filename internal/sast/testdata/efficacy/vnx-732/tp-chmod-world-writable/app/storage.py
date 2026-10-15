import os
from pathlib import Path


def prepare(upload_dir, sock_path, fd):
~>    os.chmod(upload_dir, 0o777)
~>    os.chmod(sock_path,0o666)
~>    Path("/var/lib/app/cache").chmod(0o777)
~>    os.fchmod(fd, 0o646)
~>    os.chmod(
        "/srv/shared/report.csv",
        mode=0o776,
    )
