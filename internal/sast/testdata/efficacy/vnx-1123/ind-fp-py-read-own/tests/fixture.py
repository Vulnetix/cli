import os

def load_self():
    with open(__file__, "rb") as fh:
        return fh.read()

def version():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "__version__.py")) as f:
        exec(compile(f.read(), "__version__.py", "exec"))
