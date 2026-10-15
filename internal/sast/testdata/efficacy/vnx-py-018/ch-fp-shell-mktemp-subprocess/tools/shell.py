import subprocess


def make_tmp():
    out = subprocess.run(["mktemp", "-d"], capture_output=True, text=True)
    return out.stdout.strip()
