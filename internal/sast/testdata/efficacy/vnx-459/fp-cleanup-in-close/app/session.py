import shutil
import tempfile


class Session:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="sess-")

    def close(self):
        shutil.rmtree(self.root)
