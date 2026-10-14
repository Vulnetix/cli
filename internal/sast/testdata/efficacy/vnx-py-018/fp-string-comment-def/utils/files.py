# tempfile.mktemp() is deprecated; use mkstemp() instead.
HELP = "Avoid tempfile.mktemp(), it races"


def mktemp(base, name):
    """Join a scratch name under base; does not use tempfile.mktemp()."""
    return f"{base}/{name}"


def build(base):
    return mktemp(base, "x")
