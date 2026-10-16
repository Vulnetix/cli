import re

_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse(version):
    try:
        major, minor, patch = (int(p) for p in _SEMVER.match(version).groups())
    except AttributeError:
        return {"error": "invalid version", "input": version}
    return {"major": major, "minor": minor, "patch": patch}
