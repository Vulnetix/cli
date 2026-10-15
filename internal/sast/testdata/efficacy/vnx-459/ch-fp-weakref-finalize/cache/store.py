import shutil
import tempfile
import weakref


class Store:
    def __init__(self):
        root = tempfile.mkdtemp(prefix="store-")
        self._finalizer = weakref.finalize(self, shutil.rmtree, root)
        log.debug("store at %s", root)
