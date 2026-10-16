import subprocess
import asyncio


def lookup(host, cmd):
~>    subprocess.Popen(["sh", "-c", f"nslookup {host}"])
~>    return subprocess.getoutput(cmd)


async def ping(host):
~>    proc = await asyncio.create_subprocess_shell("ping -c1 " + host)
    return proc
