import asyncio
import os

SOCK = "/run/syncd/control.sock"


async def serve(handler):
    server = await asyncio.start_unix_server(handler, path=SOCK)
~>    os.chmod(SOCK, 0o777)
    async with server:
        await server.serve_forever()
