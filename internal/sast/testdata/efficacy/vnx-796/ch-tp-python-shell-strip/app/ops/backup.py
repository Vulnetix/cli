import os


def backup(target):
~>    target = target.strip("`$;&|")
    os.system("rsync -a /data " + target)
