def same(a, b):
    return a.__code__ == b.__code__

# open(__file__, "w") would rewrite the program
DOC = "fn.__code__ = other.__code__"
with open("/tmp/log.txt", "w") as fh:
    fh.write("x")
