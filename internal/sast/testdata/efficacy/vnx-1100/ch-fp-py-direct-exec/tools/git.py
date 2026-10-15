import asyncio
import subprocess


def status(repo):
    return subprocess.run(["git", "-C", repo, "status", "--short"], capture_output=True, text=True)


async def shell_out(cmd):
    proc = await asyncio.create_subprocess_shell(cmd)
    await proc.wait()
    print("ran under the default shell, not bash")
