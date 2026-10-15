import os


class Spool:
    def __init__(self, spool_file):
        self.spool_file = spool_file

    def claim(self, uid, gid):
        if os.path.exists(self.spool_file):
~>            os.chown(self.spool_file, uid, gid)
            return True
        return False
