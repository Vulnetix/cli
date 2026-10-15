import re
import subprocess

HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
HTML_ESCAPES = {"<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;"}


def run_ping(host):
    if not HOST_RE.fullmatch(host):
        raise ValueError("invalid host")
    return subprocess.run(["ping", "-c", "1", host])


def escape(text):
    return "".join(HTML_ESCAPES.get(c, c) for c in text)
