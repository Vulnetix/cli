import marshal
import sys


def load_code(path):
    with open(path, "rb") as fh:
        fh.read(16)  # skip the pyc header
        return marshal.load(fh)


def roundtrip(obj):
    return marshal.loads(marshal.dumps(obj))


if __name__ == "__main__":
    print(load_code(sys.argv[1]).co_names)
