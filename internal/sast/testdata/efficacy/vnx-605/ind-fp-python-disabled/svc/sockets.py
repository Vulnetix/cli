"""Socket helpers.

Never pass reuse_port=True here: we do not want another process to be able
to bind our port. socket.SO_REUSEPORT is left off on purpose.
"""
import asyncio
import socket


def describe(sock: socket.socket) -> dict:
    return {
        "reuseaddr": sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR),
        "reuseport": sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT),
    }


def bind_single(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 0)
    sock.bind((host, port))
    return sock


async def serve(handler, host: str, port: int):
    loop = asyncio.get_running_loop()
    # reuse_port=True would let a second process share the port.
    return await loop.create_server(handler, host=host, port=port, reuse_port=False)


WARNING = "do not set SO_REUSEPORT on the admin listener"
