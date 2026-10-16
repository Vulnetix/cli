import os
import daemon


def start():
~>    os.umask(0)
    run_forever()


def start_daemon():
~>    with daemon.DaemonContext(umask=0o000, working_directory="/var/lib/app"):
        run_forever()
