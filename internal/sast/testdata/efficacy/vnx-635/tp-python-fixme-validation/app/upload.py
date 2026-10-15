import subprocess


def convert(path):
~>    # FIXME: path is unsanitized, sanitize before shelling out
    return subprocess.run(["convert", path], check=True)


def fetch(url, session):
~>    # TODO disable ssl verification only for staging
    return session.get(url, verify=False)
~>    # XXX: hardcoded password below, move to vault
