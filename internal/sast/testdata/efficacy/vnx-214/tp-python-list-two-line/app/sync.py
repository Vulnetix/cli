import subprocess


def sync(api_token, target):
    args = ["vaultctl", "push", "--token", api_token, target]
~>    subprocess.run(args, check=True)
