import os
import stat

SHARED = "/opt/tool/plugins"


def install(target):
    perms = 0o777
~>    os.chmod(target, perms)
~>    os.chmod(SHARED, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
~>    os.chmod(target + "/log", stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)


def legacy(path):
~>    os.chmod(path, 0777)
