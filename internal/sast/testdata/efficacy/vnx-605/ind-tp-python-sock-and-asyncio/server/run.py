import asyncio
import socket


def make_socket(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
~>    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("0.0.0.0", port))
    return sock


async def serve(handler, port):
    loop = asyncio.get_running_loop()
~>    server = await loop.create_server(handler, port=port, reuse_port=True)
    async with server:
        await server.serve_forever()
