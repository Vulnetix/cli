import subprocess


def run(step):
    # eval "$step" is what the old shell version did
    return subprocess.run(["make", step], check=True)
