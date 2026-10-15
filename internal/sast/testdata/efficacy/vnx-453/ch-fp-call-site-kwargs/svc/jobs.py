import requests
import subprocess


def nightly(url):
    resp = requests.get(url, verify=True, timeout=30)
    subprocess.run(["rsync", "-a", "src/", "dst/"], shell=False, check=True)
    return resp.json()


def fetch_secure(url, verify=True, insecure=False, debug=False, shell=False):
    return requests.get(url, verify=verify and not insecure)
