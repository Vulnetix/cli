import subprocess

def upload(path):
    subprocess.check_call([
        "curl", "-sS",
~>        "-u", "uploader:Kd73PzQw1x",
        "-T", path,
        "https://files.acme.io/upload/",
    ])
