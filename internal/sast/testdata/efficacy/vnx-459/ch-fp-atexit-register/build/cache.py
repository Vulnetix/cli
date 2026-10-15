import atexit
import shutil
import tempfile


def scratch_dir():
    scratch = tempfile.mkdtemp(prefix="cache-")
    atexit.register(shutil.rmtree, scratch, ignore_errors=True)
    print("using", scratch)
