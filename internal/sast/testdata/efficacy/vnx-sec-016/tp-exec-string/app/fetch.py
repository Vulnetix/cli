import subprocess


def fetch(url):
~>    return subprocess.check_output(f"curl --insecure {url}", shell=True)


def fetch2(url):
~>    os.system("curl -sk " + url)


def fetch3(url):
~>    subprocess.run(["curl", "-sS", "-k", "-o", "data.json", url], check=True)
    subprocess.run(["curl", "-sS", "-o", "data.json", url], check=True)
