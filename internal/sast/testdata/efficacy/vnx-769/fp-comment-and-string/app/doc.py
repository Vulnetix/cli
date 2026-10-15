EXAMPLE = """
for p in paths:
    fh = open(p)
"""


def run(paths):
    for p in paths:
        # fh = open(p)  # leaks, so we use a with-block below
        with open(p) as fh:
            print(fh.read())
