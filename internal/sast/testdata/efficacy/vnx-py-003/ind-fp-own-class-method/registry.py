import json


class Codec:
    def load(self, f):
        return json.load(f)

    def loads(self, s):
        return json.loads(s)


codec = Codec()


def read(f, s):
    return codec.load(f), codec.loads(s)
