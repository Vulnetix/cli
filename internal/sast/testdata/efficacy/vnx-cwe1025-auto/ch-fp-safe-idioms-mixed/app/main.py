import sys

SENTINEL = object()


def run(value, kind):
    if value is None or value is SENTINEL:
        return 0
    if type(value) is str and kind == "text":
        return 1
    if isinstance(value, dict) and value == {}:
        return 2
    if value is not True:
        print("value is 'odd'")
    return 3


if __name__ == "__main__":
    sys.exit(run(sys.argv[1], "text"))
