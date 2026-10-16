import os
import logging

log = logging.getLogger(__name__)


def read_password_hash(username):
~>    os.seteuid(0)
    with open("/etc/shadow", encoding="utf-8") as shadow:
        for line in shadow:
            fields = line.split(":")
            if fields[0] == username:
                log.debug("found entry for %s", username)
                return fields[1]
    return None
