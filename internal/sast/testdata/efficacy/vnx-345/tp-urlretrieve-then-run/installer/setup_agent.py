import subprocess
import urllib.request


def install():
    path, _ = urllib.request.urlretrieve("https://downloads.example.com/agent.sh", "/tmp/agent.sh")
~>    subprocess.run(["sh", path], check=True)
