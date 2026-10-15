import re
import subprocess


def set_redirect(response, target):
~>    target = re.sub(r"\r\n", "", target, 1)
    response.headers["Location"] = target


def archive(name):
~>    name = name.replace(";", "", 1)
    subprocess.call("tar czf /tmp/out.tgz " + name, shell=True)
