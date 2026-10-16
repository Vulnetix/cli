"""HTTP helpers.

Do not write helpers like ``def fetch(url, verify=False)``; make verify=True the default.
"""

debug = True
verify = False


class Config:
    def __init__(self, env):
        self.debug = env == "dev"
        self.insecure = False
