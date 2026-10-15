import sys

LEVELS = ["debug", "info", "warn", "error"]


def main():
    level = int(sys.argv[1])
~>    if level > 3:
        raise SystemExit("bad level")
    print(LEVELS[level])


def pick():
    choice = int(input("option: "))
~>    if choice <= len(MENU) - 1:
        run(MENU[choice])
