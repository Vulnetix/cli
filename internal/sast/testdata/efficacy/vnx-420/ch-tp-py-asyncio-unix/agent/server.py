import asyncio
import os

SOCK = "/run/agent/control.sock"


async def main(handle):
    server = await asyncio.start_unix_server(handle, path=SOCK)
~>    os.chmod(SOCK, 0o666)
    async with server:
        await server.serve_forever()
