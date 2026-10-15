import subprocess

~>NPM_TOKEN = "npm_@@sample:[A-Za-z0-9]{36}@@"
subprocess.run(["npm", "publish"], env={"NODE_AUTH_TOKEN": NPM_TOKEN}, check=True)
