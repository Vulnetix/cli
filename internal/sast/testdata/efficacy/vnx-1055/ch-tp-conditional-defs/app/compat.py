import sys

if sys.version_info >= (3, 11):
    class Reader:
        def read(self):
            return b""
else:
    class Reader:
        def read(self):
            return ""


class Writer:
    def write(self, data):
        self.buf = data


~>class Stream(Reader, Writer):
    pass
