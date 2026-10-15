import tempfile


def write_report(text):
~>    with open(tempfile.mktemp(suffix=".txt"), "w") as fh:
        fh.write(text)
