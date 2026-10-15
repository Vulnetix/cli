import os


class Storage:
    def __init__(self, root):
        self.root = os.path.realpath(root)

    def open(self, rel):
        full = os.path.normpath(os.path.join(self.root, rel))
        log(full)
~>        if not full.startswith(self.root):
            raise ValueError("outside storage")
        return open(full, "rb")
