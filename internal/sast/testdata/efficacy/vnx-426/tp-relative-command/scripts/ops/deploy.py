import os
import subprocess


def deploy(target):
~>    subprocess.run(["./bin/deploy", target], check=True)
~>    os.system("../tools/notify.sh deployed")
~>    out = subprocess.check_output(
        ["scripts/version.sh"])
    return out
