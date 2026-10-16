import subprocess
import tempfile


class Workspace:
    def __init__(self, repo_url):
        self.repo_url = repo_url
~>        self.workdir = tempfile.mkdtemp(prefix="checkout-")

    def build(self):
        subprocess.run(["git", "clone", self.repo_url, self.workdir], check=True)
        subprocess.run(["make", "-C", self.workdir], check=True)
