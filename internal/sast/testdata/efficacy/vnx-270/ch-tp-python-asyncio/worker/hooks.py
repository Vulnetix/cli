import asyncio
import os


async def run_hook(uid, path):
    os.seteuid(uid)
~>    proc = await asyncio.create_subprocess_exec(path, "--once")
    return await proc.wait()
