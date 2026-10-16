import asyncio
import socket

HELP = "pass reuse_port=True to share the port (we do not)"
# sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) was removed


async def serve(handler, port):
    loop = asyncio.get_running_loop()
    return await loop.create_server(handler, port=port, reuse_port=False)


def probe(sock):
    return sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT)
