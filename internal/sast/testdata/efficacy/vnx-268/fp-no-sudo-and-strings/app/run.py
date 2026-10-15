import subprocess

# subprocess.run(["sudo", "rm", path]) used to be here
HELP = "run sudo {} yourself".format("make install")


def build(target):
    subprocess.run(["make", target], check=True)
    print(f"now run: sudo make install PREFIX={target}")


def pseudo(name):
    pseudocode = f"pseudo {name}"
    subprocess.run(["echo", pseudocode])
