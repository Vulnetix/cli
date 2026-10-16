def answer():
    return eval("6 * 7")


def bootstrap(path):
    with open(path) as f:
        exec(compile(f.read(), path, "exec"))


def legacy(path):
    exec(open(path).read())
