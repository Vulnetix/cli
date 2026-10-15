import os


def own_bytes():
    with open(__file__, "rb") as fh:
        return fh.read()


def own_text():
    with open(__file__, mode="r") as fh:
        return fh.read()


HERE = os.path.dirname(os.path.abspath(__file__))


def write_report(data):
    with open(os.path.join(HERE, "report.txt"), "w") as fh:
        fh.write(data)


def is_same_code(a, b):
    return a.__code__ == b.__code__
