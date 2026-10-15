import os
import sys

JAIL = "/var/lib/app/jail"


def enter():
    os.chroot(JAIL)
    os.chdir("/")


def configure(settings):
    os.chroot(settings.JAIL_ROOT)
    sys.path.insert(0, os.path.dirname(__file__))
    sys.path.append(os.path.join(BASE_DIR, "vendor"))
