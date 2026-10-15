import contextlib
import shutil
import tempfile


def run_batch(items):
    with contextlib.ExitStack() as stack:
        work = tempfile.mkdtemp()
        stack.callback(shutil.rmtree, work)
        for item in items:
            process(item, work)
