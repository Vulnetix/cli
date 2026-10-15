import asyncio
import subprocess as sp


def clone(url):
~>    sp.run(
        f"git clone --depth 1 {url}",
        shell=True,
        check=True,
    )


async def ping(host):
~>    proc = await asyncio.create_subprocess_shell(f"ping -c 1 {host}")
    return await proc.wait()


def whois(domain):
~>    return sp.getoutput("whois %s" % domain)
