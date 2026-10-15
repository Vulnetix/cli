import daemon

from svc.server import serve


def main():
~>    with daemon.DaemonContext(umask=0o000, working_directory="/"):
        serve()
