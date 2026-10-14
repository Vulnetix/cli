import types


def from_pyfile(filename):
    d = types.ModuleType("config")
    with open(filename, mode="rb") as config_file:
        exec(compile(config_file.read(), filename, "exec"), d.__dict__)
    return d


def read_version():
    ns = {}
    exec(open("src/pkg/_version.py").read(), ns)
    return ns["__version__"]
