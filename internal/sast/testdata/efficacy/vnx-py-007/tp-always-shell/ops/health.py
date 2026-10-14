import asyncio
import subprocess


async def check(host, directory):
~>    status = subprocess.getoutput(f"ping -c 1 {host}")
~>    code, usage = subprocess.getstatusoutput("du -sh " + directory)
~>    proc = await asyncio.create_subprocess_shell(f"nc -z {host} 443")
    return status, usage, await proc.wait()
