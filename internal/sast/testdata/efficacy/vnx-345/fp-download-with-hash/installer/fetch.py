import hashlib
import subprocess
import urllib.request

EXPECTED = "@@sample:9[f]86[d]08[1]88[4]c7[d]65[9]a2[f]ea[a]0c[5]5a[d]01[5]a3[b]f4[f]1b[2]b0[b]82[2]cd[1]5d[6]c1[5]b0[f]00[a]08@@"


def install():
    path, _ = urllib.request.urlretrieve("https://downloads.example.com/agent.sh", "/tmp/agent.sh")
    with open(path, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != EXPECTED:
            raise RuntimeError("checksum mismatch")
    subprocess.run(["sh", path], check=True)


def page():
    html = requests.get("https://example.com").text
    return html
