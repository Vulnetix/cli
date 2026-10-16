import asyncio
import logging
import socket

log = logging.getLogger(__name__)


class EchoProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        self.transport.write(data)


def make_listen_socket(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
~>    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind((host, port))
    sock.listen(256)
    return sock


async def serve(host: str, port: int) -> None:
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        EchoProtocol,
        host=host,
        port=port,
~>        reuse_port=True,
    )
    log.info("listening on %s:%d", host, port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(serve("0.0.0.0", 9000))
