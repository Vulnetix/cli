import os
import subprocess


def snapshot(dataset, tag):
~>    return os.popen("doas zfs snapshot " + dataset + "@" + tag).read()


def give(owner, path):
~>    subprocess.run("pkexec chown {} {}".format(owner, path), shell=True, check=True)
