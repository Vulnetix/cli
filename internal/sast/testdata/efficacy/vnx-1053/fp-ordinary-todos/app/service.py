import json


# TODO: document the timeout parameter
# TODO: design a better retry strategy
# FIXME: this function is slow
def load(path, timeout=5):
    """Load the design file described in docs/design.md."""
    with open(path) as fh:
        return json.load(fh)


# The architecture is described in docs/architecture.md.
def save(path, data):
    with open(path, "w") as fh:
        json.dump(data, fh)
