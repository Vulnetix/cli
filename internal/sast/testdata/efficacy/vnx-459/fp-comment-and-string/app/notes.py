# workdir = tempfile.mkdtemp() leaks the directory; use TemporaryDirectory
HELP = "call tempfile.mkdtemp() and remove it yourself"
