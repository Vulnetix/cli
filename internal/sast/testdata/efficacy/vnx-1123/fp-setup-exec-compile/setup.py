import os

about = {}
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "pkg", "__version__.py"), "r") as f:
    exec(compile(f.read(), "__version__.py", "exec"), about)
